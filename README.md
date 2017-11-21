# Datagram-Packet-Analyzer
This project analyzes the hex dump of a datagram packet and outputs the detailed IP and TCP, UDP or ICMP headers.
This code is written using Java version 8

Steps to run the code:

1. Store the java file in any directory 

2. Open command prompt in that same directory

3. Type javac Pktanalyzer.java

4. Then to run it, type Java Pktanalyzer "path_of_the_bin_packet"

	For example,     java Pktanalyzer "C:\new_tcp_packet1.bin"
	Another example, java Pktanalyzer "C:\Users\Renzil Dourado\Downloads\new_tcp_packet1.bin"
	Sample input packets are provided  in the "Input packets" folder
	
	If the bin file is in the same directory as the java file, you just need to specify the filename.
	For example,    java Pktanalyzer "new_tcp_packet1.bin"
	
5. This code takes the first argument as the path of the .bin file to be analyzed
	
6. The path should be specified in quotes so that the code does not blow up if there is a space in the file path like in the second example "Renzil Dourado"
