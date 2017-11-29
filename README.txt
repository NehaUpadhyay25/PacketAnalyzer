Author : Neha Upadhyay
RIT Id : nxu3128@rit.edu

How to run:
Open the command prompt.
Javac Packetanalyzer.java
java Packetanalyzer "path of the file in your system where the packets are placed"

PacketAnalyzer.java is implemented to analyse TCP, UDP and ICMP packets. This class takes the packet format as ".bin" file. The input is given by the user as Command line argument. Ex: "C:/Users/Rishabh Upadhyay/Downloads/Packet Analyzer/new_tcp_packet.bin".
Given this input, it analyzes the packet and prints the IP, Ether and corresponding protocol headers of the given packet.