**Overview**

This project simulates a basic cyber forensics workflow by capturing live network traffic, analyzing packet data, and generating structured reports. The implementation is written in Python and operates within a controlled environment.

**Setup**

Environment: Kali Linux running on Windows Subsystem for Linux

Python virtual environment (venv) for dependency management

Required system tool: tcpdump for packet capture

**Execution**

-The script is executed with elevated privileges to allow packet capture

-Network traffic is captured from the system interface (eth0)

-Captured packets are stored in .pcap format

-The data is then processed and analyzed using Python libraries

**Output**

The program generates the following inside the outputs/ directory:

- Packet capture file (.pcap)

-Traffic summary (.csv)

Visualizations:

-Protocol usage

-Top IP addresses

-Top ports

-Packet size distribution

-Packets over time

-Final PDF report combining all analysis

Description

This project demonstrates how network traffic can be intercepted, analyzed, and documented to simulate a cyber forensics investigation. It provides insight into packet-level activity and basic traffic patterns within a system.
