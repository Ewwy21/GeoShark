#!/usr/bin/env python3

import pyshark
import sys
import re
import json
import dpkt
from functools import reduce
import socket
from scapy.all import *





cap = pyshark.FileCapture('/home/kali/blueteam/sift/rhino.log')
def print_info_layer(packet):
        print("[Protocol:] "+packet.highest_layer+" [Source IP:] "+packet.ip.src+" [Destination IP:]")
cap.apply_on_packets(print_info_layer)

if __name__ == "__main__":

# Packet Counters
    counter=0
    ipcounter=0
    nonipcounter=0    
    tcpcounter=0
    udpcounter=0
    httpcounter=0
    httpscounter=0
    ipv4counter=0
    ipv6counter=0

    # Subnet Dictionary
    subnets = {}

    # Open file

    # Packet processing loop
    for ts,pkt in dpkt.pcap.Reader(open('/home/kali/blueteam/sift/rhino.log','rb')):
        counter+=1

         # Parse ethernet packet
        eth=dpkt.ethernet.Ethernet(pkt)
        ip=eth.data       

        #check if IP packet or non-ip packet
        if eth.type == dpkt.ethernet.ETH_TYPE_IP or eth.type == dpkt.ethernet.ETH_TYPE_IP6:
            ipcounter = ipcounter + 1
        else:
            nonipcounter = nonipcounter + 1    

        # IPV6 packets
        if eth.type==dpkt.ethernet.ETH_TYPE_IP6: 
            ipv6counter+=1     


        # IPV4 packets
        elif eth.type==dpkt.ethernet.ETH_TYPE_IP:
            ipv4counter+=1

            # Extract destination
            string = socket.inet_ntoa(ip.dst)
            address = '.'.join(string.split(".")[:]) 
            if address in subnets: #increase count in dict
                subnets[address] = subnets[address] + 1
            else: #insert key, value in dict
                subnets[address] = 1            

            # TCP packets
           if ip.p==dpkt.ip.IP_PROTO_TCP: #ip.p == 6: 
                tcpcounter+=1
                tcp=ip.data

                # HTTP uses port 80
                if tcp.dport == 80 or tcp.sport == 80:
                    httpcounter+=1

                # HTTPS uses port 443
                elif tcp.dport == 443 or tcp.sport == 443:
                    httpscounter+=1


            # UDP packets
            elif ip.p==dpkt.ip.IP_PROTO_UDP: #ip.p==17:
                udpcounter+=1
                udp=ip.data



    # Print packet totals
    print ("\n"+">>>>PCAP FILE SUMMARY<<<<"+"\n")
    print ("Total number of ETHERNET packets in the PCAP file :", counter)
    print ("Total number of IP packets :", ipcounter)
    print ("Total number of TCP packets :", tcpcounter)
    print ("Total number of HTTP packets :", httpcounter)
    print ("Total number of HTTPS packets :", httpscounter)
    print ("Total number of IPV6 packets :", ipv6counter)
    print ("Total number of UDP packets :", udpcounter)    
    print ("Total number of IPV4 packets :", ipv4counter)
    print ("Total number of NON-IP packets :", nonipcounter)
    print ("--------------------------------------------------------------")
    other = counter-(arpcounter+httpcounter+httpscounter+ipv6counter)



    # Print addresses
    print ("Address \t \t Occurences")
    for key, value in sorted(subnets.items(), key=lambda t: int(t[0].split(".")[0])):
        print ("%s/16 \t = \t %s" %(key, value))
