import struct
from collections import Counter

def readPcapFile(filesPath):
    packetsArray = []
    countPackets = 0

    for filePath in filesPath:
        filePackets = []

        with open(filePath, 'rb') as f:
            # Read the pcap file header
            pcap_header = f.read(24)

            while True:
                # Read the packet header
                packetHeaderInfo = f.read(16)
                if not packetHeaderInfo:
                    break

                # Extract timestamp and packet length from the packet header
                secondTimeStamp, microSecTimeStamp, length, originalLength = struct.unpack('<IIII', packetHeaderInfo)

                # Read the packet data
                packet = f.read(length)

                # Store the packet data
                filePackets.append((secondTimeStamp, microSecTimeStamp, packet))
                countPackets += 1

        packetsArray.append(filePackets)
        print(f"File '{filePath}' has {len(filePackets)} packets.")

    return packetsArray, countPackets

def countPacketsBasedOnIp(packetsArray):
    ipPacketCount = Counter()

    for packets in packetsArray:
        for secondTimeStamp, microSecTimeStamp, packetInfo in packets:
            # Extract source IP address (assuming IPv4)
            sourceIpPacket = '.'.join(map(str, packetInfo[26:30]))

            # Increment packet count for the source IP
            ipPacketCount[sourceIpPacket] += 1

    # Sort IP addresses by packet count in descending order
    sortedIpPacketCount = sorted(ipPacketCount.items(), key=lambda key: key[1], reverse=True)

    return sortedIpPacketCount


def countPacketBasedOnDestinationPort(packetsArray):
    countTcpPort = Counter()

    for packets in packetsArray:
        for secondTimeStamp, microSecTimeStamp, packetInfo in packets:
            # Check if packet contains TCP layer
            if packetInfo[12] == 0x08 and packetInfo[13] == 0x00 and packetInfo[23] == 0x06:
                # Extract destination TCP port
                destinationPort = struct.unpack('!H', packetInfo[36:38])[0]

                # Increment packet count for the destination TCP port
                countTcpPort[destinationPort] += 1

    # Sort TCP ports by packet count in descending order
    sortedTcpPortCount= sorted(countTcpPort.items(), key=lambda key: key[1], reverse=True)

    return sortedTcpPortCount

def distinctIpPortPairsCount(packetsArray):
    ipPortPairs = Counter()

    for packets in packetsArray:
        for secondTimeStamp, microSecTimeStamp, packetInfo in packets:
            # Check if packet contains Ethernet, IP, and TCP layers
            if len(packetInfo) >= 54 and packetInfo[12] == 0x08 and packetInfo[13] == 0x00 and packetInfo[23] == 0x06:
                # Extract source IP address (assuming IPv4)
                sourceIp = '.'.join(map(str, packetInfo[26:30]))

                # Extract destination TCP port
                destinationPort = struct.unpack('!H', packetInfo[36:38])[0]

                # Create a tuple representing the IP and port pair
                ipPortPair = (sourceIp, destinationPort)

                # Increment count for the IP and port pair
                ipPortPairs[ipPortPair] += 1

    # Sort IP and port pairs by count in descending order
    sortedIpPortPairCount = sorted(ipPortPairs.items(), key=lambda key: key[1], reverse=True)

    return sortedIpPortPairCount

# Usage
filesPath = ['file1.pcap', 'file2.pcap', 'file3.pcap']  # List of file paths

print("*********************************************************************************************************")
print("---Question 1 : Determine the number of packets in each pcap file and the total number in all the pcap files---")
print("*********************************************************************************************************")

# Question 1: Determine the number of packets in each pcap file and the total number in all the pcap files
packetsArray, totalPackets = readPcapFile(filesPath)
print(f"Total packets in overall pcap files: {totalPackets}\n")

# Question 2: Identify distinct source IP addresses and the number of packets for each IP address, sorting them in descending order
sortedIpPacketCount = countPacketsBasedOnIp(packetsArray)
print("\n*********************************************************************************************************")
print("---Question 2: Distinct Source IP Addresses and Number of Packets (Descending Order):---")
print("*********************************************************************************************************")

for sourceIp, packetCount in sortedIpPacketCount:
    print(f"Source IP Address: {sourceIp}, Number Of Packets: {packetCount}")

# Question 3: List distinct destination TCP ports and the number of packets sent to each port in descending order
sortedTcpPairCount = countPacketBasedOnDestinationPort(packetsArray)

print("\n*********************************************************************************************************")
print("      ---Question 3: Distinct Destination TCP Ports and Number of Packets (Descending Order):---")
print("*********************************************************************************************************")
for destinationPort, packetCount in sortedTcpPairCount:
    print(f"Destination Port: {destinationPort}, Packets: {packetCount}")


# Question 4: Calculate the number of distinct source IP and destination TCP port pairs, sorting them in descending order
sorted_ip_port_pairs = distinctIpPortPairsCount(packetsArray)
print("\n*********************************************************************************************************")
print("    ---Question4: Distinct Source IP and Destination TCP Port Pairs and Their Occurrences (Descending Order):")
print("*********************************************************************************************************")
for pair, count in sorted_ip_port_pairs:
    print(f"Source IP: {pair[0]}, Destination TCP Port: {pair[1]}, Total number Of Packets: {count}")