#!/usr/bin/python

"""
"""
import re
import sys
import os

from mininet.log import setLogLevel, debug, info, error,lg
from mininet.net import Mininet
from mininet.link import Intf,TCIntf
from mininet.util import custom,quietRun,irange,dumpNodeConnections
from mininet.cli import CLI
from mininet.node import Node,Controller,RemoteController,OVSKernelSwitch
from mininet.topo import Topo
from mininet.node import CPULimitedHost
from mininet.link import TCLink

from subprocess import Popen, PIPE
from time import sleep, time
from multiprocessing import Process
from argparse import ArgumentParser


rs_bw=50 #root to switch
dhs_bw=50#dhcpserver to switch
ss_bw=50 #switch to switch
hs_bw=50 #host to switch

c_bw=5

# Parse arguments

parser = ArgumentParser(description="Traffic tests")
parser.add_argument('--rs_bw', '-RS',
                    dest="rs_bw",
                    type=float,
                    action="store",
                    help="Bandwidth between root(Internet) and switch1",
                    required=True)

parser.add_argument('--ss_bw', '-SS',
                    dest="ss_bw",
                    type=float,
                    action="store",
                    help="Bandwidth between any two switches",
                    required=True)

parser.add_argument('--dhs_bw', '-DHS',
                    dest="dhs_bw",
                    type=float,
                    action="store",
                    help="Bandwidth between a dhcp server and a switch",
                    required=True)

parser.add_argument('--hs_bw', '-HS',
                    dest="hs_bw",
                    type=float,
                    action="store",
                    help="Bandwidth between hosts and switchs",
                    required=True)

parser.add_argument('--c_bw', '-C',
                    dest="c_bw",
                    type=float,
                    action="store",
                    help="Bandwidth between real hosts and switchs",
                    required=True)

parser.add_argument('--delay',
                    dest="delay",
                    type=float,
                    help="Delay in milliseconds of host links",
                    default=10)

parser.add_argument('--dir', '-d',
                    dest="dir",
                    action="store",
                    help="Directory to store outputs",
                    default="results",
                    required=True)

parser.add_argument('--k',
                    dest="k",
                    type=int,
                    action="store",
                    help="Fanout (Number of switches)",
                    required=True)

parser.add_argument('--maxq',
                    dest="maxq",
                    action="store",
                    help="Max buffer size of network interface in packets",
                    default=100)

parser.add_argument('--cong',
                    dest="cong",
                    help="Congestion control algorithm to use",
                    default="reno")

parser.add_argument('--diff',
                    help="Enabled differential service", 
                    action='store_true',
                    dest="diff",
                    default=False)

parser.add_argument('--intf',
                    dest="intf",
                    type=str,
                    action="store",
                    help="Real Interface",
                    required=True)


# Expt parameters
args = parser.parse_args()



#################################
def startNAT( root, inetIntf='eth0', subnet='10.0/8' ):
    """Start NAT/forwarding between Mininet and external network
root: node to access iptables from
inetIntf: interface for internet access
subnet: Mininet subnet (default 10.0/8)="""

    # Identify the interface connecting to the mininet network
    localIntf = root.defaultIntf()

    # Flush any currently active rules
    root.cmd( 'iptables -F' )
    root.cmd( 'iptables -t nat -F' )

    # Create default entries for unmatched traffic
    root.cmd( 'iptables -P INPUT ACCEPT' )
    root.cmd( 'iptables -P OUTPUT ACCEPT' )
    root.cmd( 'iptables -P FORWARD DROP' )

    # Configure NAT
    root.cmd( 'iptables -I FORWARD -i', localIntf, '-d', subnet, '-j DROP' )
    root.cmd( 'iptables -A FORWARD -i', localIntf, '-s', subnet, '-j ACCEPT' )
    root.cmd( 'iptables -A FORWARD -i', inetIntf, '-d', subnet, '-j ACCEPT' )
    root.cmd( 'iptables -t nat -A POSTROUTING -o ', inetIntf, '-j MASQUERADE' )

    # Instruct the kernel to perform forwarding
    root.cmd( 'sysctl net.ipv4.ip_forward=1' )

def stopNAT( root ):
    """Stop NAT/forwarding between Mininet and external network"""
    # Flush any currently active rules
    root.cmd( 'iptables -F' )
    root.cmd( 'iptables -t nat -F' )

    # Instruct the kernel to stop forwarding
    root.cmd( 'sysctl net.ipv4.ip_forward=0' )

def fixNetworkManager( root, intf ):
    """Prevent network-manager from messing with our interface,
by specifying manual configuration in /etc/network/interfaces
root: a node in the root namespace (for running commands)
intf: interface name"""
    cfile = '/etc/network/interfaces'
    line = '\niface %s inet manual\n' % intf
    config = open( cfile ).read()
    if ( line ) not in config:
        print '*** Adding', line.strip(), 'to', cfile
        with open( cfile, 'a' ) as f:
            f.write( line )
    # Probably need to restart network-manager to be safe -
    # hopefully this won't disconnect you
    root.cmd( 'service network-manager restart' )

def connectToInternet( network,switch='s1', rootip='10.254', subnet='10.0/24'):
    """Connect the network to the internet
switch: switch to connect to root namespace
rootip: address for interface in root namespace
subnet: Mininet subnet"""
    switch = network.get( switch )
    prefixLen = subnet.split( '/' )[ 1 ]

    # Create a node in root namespace
    root = Node( 'root', inNamespace=False )

    # Prevent network-manager from interfering with our interface
    fixNetworkManager( root, 'root-eth0' )

    # Create link between root NS and switch
    link = network.addLink( root, switch,bw=args.rs_bw,max_queue_size=int(args.maxq),use_htb=True)
    link.intf1.setIP( rootip, prefixLen )
    # Start network that now includes link to root namespace
    network.start()
    
    # Start NAT and establish forwarding
    startNAT( root )

    # Setting up DHCP
    print "IF 0 ROOT ->" + str(os.getuid())
    out = network.hosts[0].cmd('sudo dhcpd')
    print "DHCPD = " + out

# Establish routes from end hosts
    for host in network.hosts:
        host.cmd( 'ip route flush root 0/0' )
        host.cmd( 'route add -net', subnet, 'dev', host.defaultIntf() )
        host.cmd( 'route add default gw', rootip )

    return root

def checkIntf( intf ):
    "Make sure intf exists and is not configured."
    if ( ' %s:' % intf ) not in quietRun( 'ip link show' ):
        error( 'Error:', intf, 'does not exist!\n' )
        exit( 1 )
    ips = re.findall( r'\d+\.\d+\.\d+\.\d+', quietRun( 'ifconfig ' + intf ) )
    if ips:
        error( 'Error:', intf, 'has an IP address,'
               'and is probably in use!\n' )
        exit( 1 )


class NewTopo(Topo):
   "Linear topology of k switches, with one host per switch."

   def __init__(self, k=2, ss_bw=50, dhs_bw=50, hs_bw=50, 
                maxq=None, diff=False):
       """Init.
k: number of switches (and hosts)
hconf: host configuration options
lconf: link configuration options"""
       super(NewTopo, self).__init__()
       self.k = k
       dhcp = self.addHost('dhcp')
       lastSwitch = None
       for i in irange(1, k):
           host = self.addHost('h%s' % i)
           switch = self.addSwitch('s%s' % i)
           self.addLink(host,switch,bw=hs_bw, max_queue_size=int(maxq), use_htb=True)
           if lastSwitch:
               self.addLink(switch,lastSwitch,bw=ss_bw, max_queue_size=int(maxq), use_htb=True)
	   lastSwitch = switch
       self.addLink(dhcp,switch,bw=dhs_bw, max_queue_size =int(maxq), use_htb=True)


topos = { 'mytopo': ( lambda: NewTopo() ) }



if __name__ == '__main__':
    lg.setLogLevel( 'info')

    # try to get hw intf from the command line; by default, use eth1
    # intfName = sys.argv[ 1 ] if len( sys.argv ) > 1 else 'eth1'
    intfName = args.intf
    info( '*** Connecting to hw intf: %s' % intfName )

    info( '*** Checking', intfName, '\n' )
    checkIntf( intfName )

    info( '*** Creating network\n' )
    topo = NewTopo(k=args.k,ss_bw=args.ss_bw,dhs_bw=args.dhs_bw,hs_bw=args.hs_bw,
                   maxq=args.maxq,diff=args.diff)
    net = Mininet(topo = topo, host = CPULimitedHost, link=TCLink)

    switch = net.switches[ 1 ]
    info( '*** Adding hardware interface', intfName, 'to switch',
          switch.name, '\n' )
    _intf = TCIntf( intfName, node=switch ,bw=args.c_bw,max_queue_size=int(args.maxq))
    info( '*** Note: you may need to reconfigure the interfaces for '
         'the Mininet hosts:\n', net.hosts, '\n' )
    
    print "\nhaha\n"
    print _intf
    print "\nhaha\n"

    net.addController('c0',controller=RemoteController,ip='149.171.37.125')
    # Configure and start NATted connectivity
    rootnode = connectToInternet( net )
    print "*** Hosts are running and should have internet connectivity"
    print "*** Type 'exit' or control-D to shut down network"
    CLI( net )
    # Shut down NAT
    net.hosts[0].cmd('killall -9 dhcpd')
    stopNAT( rootnode )
    net.stop()
    Popen("killall -9 cat", shell=True).wait()


