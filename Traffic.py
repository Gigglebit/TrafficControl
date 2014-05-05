#!/usr/bin/python

"""
Example to create a Mininet topology and connect it to the internet via NAT
through eth0 on the host.

Glen Gibb, February 2011

(slight modifications by BL, 5/13)
"""
import re
import sys
import os

from mininet.log import setLogLevel, debug, info, error,lg
from mininet.net import Mininet
from mininet.link import Intf,TCIntf
from mininet.util import custom,quietRun,irange,dumpNodeConnections
from mininet.cli import CLI
from mininet.node import Node
from mininet.topo import Topo
from mininet.node import CPULimitedHost
from mininet.link import TCLink

rs_bw=50 #root to switch
dhs_bw=50#dhcpserver to switch
ss_bw=50 #switch to switch
hs_bw=50 #host to switch

connection_bw=5


#################################
def startNAT( root, inetIntf='eth0', subnet='10.0/8' ):
    """Start NAT/forwarding between Mininet and external network
    root: node to access iptables from
    inetIntf: interface for internet access
    subnet: Mininet subnet (default 10.0/8)="""

    # Identify the interface connecting to the mininet network
    localIntf =  root.defaultIntf()

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

def connectToInternet( network, switch='s1', rootip='10.254', subnet='10.0/24'):
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
    link = network.addLink( root, switch,bw=rs_bw,max_queue_size=100,use_htb=True)
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

   def __init__(self, k=2, **opts):
       """Init.
           k: number of switches (and hosts)
           hconf: host configuration options
           lconf: link configuration options"""

       super(NewTopo, self).__init__(**opts)

       self.k = k

       dhcp = self.addHost('dhcp')

       lastSwitch = None
       for i in irange(1, k):
           host = self.addHost('h%s' % i)
           switch = self.addSwitch('s%s' % i)
           self.addLink(host,switch,bw=hs_bw, max_queue_size=100, use_htb=True)
           if lastSwitch:
               self.addLink(switch,lastSwitch,bw=ss_bw, max_queue_size=100, use_htb=True)
           lastSwitch = switch
       self.addLink(dhcp,switch,bw=dhs_bw, max_queue_size = 100, use_htb=True)

topos = { 'mytopo': ( lambda: NewTopo() ) }



if __name__ == '__main__':
    lg.setLogLevel( 'debug')

    # try to get hw intf from the command line; by default, use eth1
    intfName = sys.argv[ 1 ] if len( sys.argv ) > 1 else 'eth1'
    info( '*** Connecting to hw intf: %s' % intfName )

    info( '*** Checking', intfName, '\n' )
    checkIntf( intfName )

    info( '*** Creating network\n' )
    topo = NewTopo(k=2)
    net = Mininet(topo = topo, host = CPULimitedHost, link=TCLink)

    switch = net.switches[ 1 ]
    info( '*** Adding hardware interface', intfName, 'to switch',
          switch.name, '\n' )
    _intf = TCIntf( intfName, node=switch ,bw=connection_bw,max_queue_size=100)
    info( '*** Note: you may need to reconfigure the interfaces for '
          'the Mininet hosts:\n', net.hosts, '\n' )
    
    #    _intf.config(bw=connection_bw,max_queue_size=100)    
    print "\nhaha\n" 
    print _intf
    print "\nhaha\n" 
    #_tcinf.config(bw=5)


    # net = TreeNet( depth=1, fanout=4 )
    # Configure and start NATted connectivity
    rootnode = connectToInternet( net )
    print "*** Hosts are running and should have internet connectivity"
    print "*** Type 'exit' or control-D to shut down network"
    CLI( net )
    # Shut down NAT
    net.hosts[0].cmd('killall -9 dhcpd')
    stopNAT( rootnode )
    net.stop()



