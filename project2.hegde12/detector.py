import dpkt
import sys
import socket
from dpkt.compat import compat_ord

f = open(sys.argv[-1],'rb')
pcap = dpkt.pcap.Reader(f)

host_ips_syn={} #dictionary to store ips initiating a tcp/ip handshake
host_ips_syn_ack={} #dictionary to store ips participating in the 2nd step of the tcp-ip handhsake

for timestamp,buf in pcap:

	try:
		eth = dpkt.ethernet.Ethernet(buf)
	except (dpkt.dpkt.UnpackError,IndexError):
		continue


	if not isinstance(eth.data, dpkt.ip.IP):
		continue

	ip = eth.data
	ip_src = socket.inet_ntoa(ip.src)
	ip_dst = socket.inet_ntoa(ip.dst)

    # We are only interested in TCP
	if ip.p != dpkt.ip.IP_PROTO_TCP:
		continue

	tcp = ip.data

	if tcp.flags & dpkt.tcp.TH_SYN and not (tcp.flags & dpkt.tcp.TH_ACK):  	    #If syn flag in the packet   
		if ip_src in host_ips_syn:     #if this ip exists in the host ips sending syn, add count 
			host_ips_syn[ip_src] += 1
		else:
			host_ips_syn[ip_src] = 1 	#else add ip to the map and initialize

	if (tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK):	 	#If syn and ack flags in the packet
		if ip_dst in host_ips_syn_ack: 	#if the ip exists among host ips receiving syn-ack packets, add count
			host_ips_syn_ack[ip_dst] += 1
		else:
			host_ips_syn_ack[ip_dst] = 1 #else add ip to map initialize



ips = []
#For every ip in the source ips, compare the count syn+ack it received vs syn it sent 
for ip in host_ips_syn: 
	if ip in host_ips_syn_ack and host_ips_syn[ip]>=3*host_ips_syn_ack[ip]: #if that ip exists among host ips receiveing syn-ack packets and if the number of syn packets >= 3* number of destination syn+ack packets, add that ip
		ips.append(ip)
	elif ip not in host_ips_syn_ack and host_ips_syn[ip]: #If that ip doesn't exist in the among host ips receiveing syn-ack packets and if number of syn packets >= 3, add that ip
		ips.append(ip)



for i in ips:
	print(i)
