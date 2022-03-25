# A program for sniffing all the DNS packets 
* This program uses the pcap library to sniff all the dns packets (UDP packets that uses the port 53)
* For some reason the any interface doesn't work on my WSL session so i had to set the interface to eth0 (WSL virtual ethernet) to see packets
* i modified the printing from a log file to stdout  
