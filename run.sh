#!/bin/bash

echo "Traffic Tests Start"
sudo sysctl -w net.ipv4.tcp_congestion_control=reno
python Traffic.py --rs_bw 50 \
                  --ss_bw 50 \
                  --dhs_bw 50 \
                  --hs_bw 50 \
                  --c_bw 5\
                  --dir ./ \
                  --maxq 100 \
                  --k 2 \
                  --intf eth1 \

echo "cleaning up..."
killall -9 iperf ping
mn -c > /dev/null 2>&1
echo "Done"


