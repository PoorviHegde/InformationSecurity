import pyshark

capture = pyshark.FileCapture('project2_part2.pcap', display_filter = 'tcp')

ip_srcs = {}

for packet in capture:

    ip_src = packet.ip.src
    ip_dst = packet.ip.dst
    seq_no = packet.tcp.seq

    if(ip_src in ip_srcs):
        ip_srcs[ip_src].append((ip_dst,seq_no))
    else:
        ip_srcs[ip_src] = [(ip_dst,seq_no)]



