## Project Summary: Network Traffic Analysis and Probing/Scanning Detection

### Overview
This project entails the development of Python scripts to analyze network traffic captured in pcap files and to identify probing and scanning activities within the network. 

### Part 1: Analyzing Network Traffic
#### Key Objectives:
1. Determine the number of packets in each pcap file and the total number across all files.
2. Identify distinct source IP addresses and the number of packets for each IP address, sorted in descending order.
3. List distinct destination TCP ports and the number of packets sent to each port in descending order.
4. Calculate the number of distinct source IP and destination TCP port pairs, sorted in descending order.

### Part 2: Probing/Scanning Detection
#### Key Objectives:
- Develop a Python script to identify probing and scanning activities within a stream of packets.
- Define probing and scanning based on clusters of points within the time-versus-port space.
- Determine clusters using parameters such as width (Wp and Ws) and the minimum number of points (Np and Ns).
- Read pcap files, identify probes and scans for TCP and UDP packets separately, and output results including identified probes and scans and their source IPs.

### Implementation Strategy:
- Read packets from pcap files and sort them by time and port number for TCP and UDP separately.
- Identify clusters within the sorted packets using specified width and minimum packet parameters.
- Output identified probes and scans along with their source IP addresses for TCP and UDP packets.

### Submission Details:
- Include the Python script file `part2.py` for probing and scanning detection.
- Provide the output file `part2_output.txt` in a text format containing the identified probes and scans along with their source IP addresses.

### Recommended Strategy:
- Build lists of packets sorted by time and port number.
- Identify clusters within the lists based on specified parameters.
- Output identified probes and scans along with their source IP addresses.

### Note:
- Ensure proper sorting and clustering of packets to accurately detect probing and scanning activities.

This project aims to provide insights into network traffic patterns and detect potentially malicious activities such as probing and scanning.
