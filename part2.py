import struct
import socket
import argparse

# Ethernet header lengths
ETH_LEN = 14

# Constants for the PCAP Global Header format (assuming Ethernet, IPv4, and TCP/UDP)
PCAP_GLOBAL_HEADER_FMT = '@IHHiIII'

# PCAP Packet Header format
PCAP_PACKET_HEADER_FMT = '@IIII'

def inet_to_str(inet):
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return False

def process_pcap_file(pcap_file_name, target_ip_address):

    with open(pcap_file_name, 'rb') as file:
        global_header = file.read(24)
        if len(global_header) < 24:
            raise ValueError('Invalid pcap file as length of global header is less than 24')

        # Parse the global header
        _, _, _, _, _, _, network = struct.unpack(PCAP_GLOBAL_HEADER_FMT, global_header)
        
        pcap_packet_data = {}

        while True:
            packet_header = file.read(16)
            if len(packet_header) < 16:
                break  # End Of file
            
            captured_time_sec, ts_usec, incl_len, orig_len = struct.unpack(PCAP_PACKET_HEADER_FMT, packet_header)
            pkt_data = file.read(incl_len)
            eth_header = pkt_data[:ETH_LEN]
            eth_fields = struct.unpack('!6s6sH', eth_header)
            eth_protocol = socket.ntohs(eth_fields[2])

            if eth_protocol == 8:  # IPv4
                ip_header = pkt_data[ETH_LEN:20+ETH_LEN]
                iph = struct.unpack('!BBHHHBBH4s4s', ip_header)
                version_ihl = iph[0]
                ihl = version_ihl & 0xF
                iph_length = ihl * 4
                protocol = iph[6]
                s_addr = socket.inet_ntoa(iph[8])
                d_addr = socket.inet_ntoa(iph[9])
                
                if d_addr == target_ip_address:

                    if protocol == 6:  # Filtering of packets for TCP protocol
                        t = captured_time_sec + (ts_usec / 1000000)
                        tcp_header = pkt_data[ETH_LEN+iph_length:ETH_LEN+iph_length+20]
                        tcph = struct.unpack('!HHLLBBHHH', tcp_header)
                        source_port, dest_port, sequence, acknowledgement, doff_reserved, tcph_flags, tcph_window, tcph_checksum, tcph_urgptr = tcph
                        doff_reserved = tcph[4]
                        tcph_length = doff_reserved >> 4

                        p_data = (t, s_addr, d_addr, source_port, dest_port)
                        pcap_packet_data.setdefault(d_addr, []).append(p_data)

                    elif protocol == 17:  # Filtering of packets for UDP Protocol
                        # Parsing the UDP header
                        t = captured_time_sec + (ts_usec / 1000000)
                        udp_header = pkt_data[ETH_LEN + iph_length:ETH_LEN + iph_length + 8]
                        udph = struct.unpack('!HHHH', udp_header)
                        source_port, dest_port, length, checksum = udph

                        packet_data = (t, s_addr, d_addr, source_port, dest_port)
                        pcap_packet_data.setdefault(d_addr, []).append(packet_data)

        # packet_data contains all packets having target_ip        
        return pcap_packet_data

def probing_packets(packet_data,width_probe,min_probe):
    probes = []

    for dest_ip, packets in packet_data.items():
        
        packets.sort(key=lambda packet: (packet[4], packet[0]))
        
        current_probe = [packets[0]]
    
    #iterating the packets
        for pkt in packets[1:]:
            # Check for probes (packets within a time window to the same port)
            if (pkt[0] - current_probe[-1][0] <= width_probe) and (pkt[4] == current_probe[-1][4]):
                current_probe.append(pkt)
            else:
                if len(current_probe) >= min_probe:
                    probes.append(current_probe)
                current_probe = [pkt]

        # Check for the last cluster
        if len(current_probe) >= min_probe:
            probes.append(current_probe)

    return probes


#Part 2 methods
def calculate_distance_between_points(point1, point2):
    return ((point1[0] - point2[0])**2 + (point1[4] - point2[4])**2)**0.5

def assign_cluster_of_packets(point, clusters, width):

    for cluster in clusters:
        for p in cluster:
            if calculate_distance_between_points(point, p) <= width:
                cluster.append(point)
                return True
    return False


def scanning_packets(packet_data,width_scan, min_points_in_cluster):    
    clusters_data = []
    for dest_ip, packets in packet_data.items():      
        
        for point in packets:
            if not assign_cluster_of_packets(point, clusters_data, width_scan):
                clusters_data.append([point])

    clusters_data = [cluster for cluster in clusters_data if len(cluster) >= min_points_in_cluster]

    return clusters_data

parser = argparse.ArgumentParser(description='PCAP Probing and Scanning Detection')
parser.add_argument('-f', '--file', help='Filename of the pcap file', required=True)
parser.add_argument('-t', '--target', help='Target IP address', required=True)
parser.add_argument('-l', '--width_probe', type=int, help='The width for probing in seconds', required=True)
parser.add_argument('-m', '--min_probe', type=int, help='The minimum number of packets for a probing', required=True)
parser.add_argument('-n', '--width_scan', type=int, help='The width for scanning in port IDs', required=True)
parser.add_argument('-p', '--min_scan', type=int, help='The minimum number of packets for a scanning', required=True)


args = parser.parse_args()

packet_data = process_pcap_file(args.file, args.target)
probes = probing_packets(packet_data,args.width_probe,args.min_probe)
scanned_clusters = scanning_packets(packet_data, args.width_scan, args.min_scan)

# Output the results for probeing and scanning
with open('probes_output.txt', 'w') as probed_file, open('scans_output.txt', 'w') as scanned_file:
    
    probed_file.write('Probes Detected:\n')
    for probe in probes:
        src_ips = set(p[1] for p in probe)
        probed_file.write(f'Probe to port {probe[0][4]} from IPs: {", ".join(src_ips)}\n')
        probed_file.write(f'Total packets: {len(probe)}\n\n')

    scanned_file.write('Scans Detected:\n')
    for scan in scanned_clusters:
        src_ips = set(p[1] for p in scan)
        scanned_file.write(f'Scan across ports {min([packet[-1] for packet in scan])} to {max([packet[-1] for packet in scan])} from IPs: {", ".join(src_ips)}\n')
        scanned_file.write(f'Total packets: {len(scan)}\n\n')