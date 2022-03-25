/*
 * pcap_example.c
 *
 *  Created on: Apr 28, 2016
 *      Author: jiaziyi
 */


#include<pcap.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include "header.h"

#include<sys/socket.h>
#include<arpa/inet.h>

#include "pcap_example.h"
#include "header.h"

//some global counter
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;


int main(int argc, char *argv[])
{
	 pcap_t *handle;		/* Session handle */
	 char dev[] = "eth0";		/* Device to sniff on */
	 char errbuf[PCAP_ERRBUF_SIZE];	/* Error string */
	 struct bpf_program fp;		/* The compiled filter expression */
	 char filter_exp[] = "port 53";	/* The filter expression */
	 bpf_u_int32 mask;		/* The netmask of our sniffing device */
	 bpf_u_int32 net;		/* The IP of our sniffing device */
 
	 if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		 fprintf(stderr, "Can't get netmask for device %s\n", dev);
		 net = 0;
		 mask = 0;
	 }
	 handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	 if (handle == NULL) {
		 fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		 return(2);
	 }
	 if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
		 fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 return(2);
	 }
	 if (pcap_setfilter(handle, &fp) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 return(2);
	 }


	//open the device
	//
	//	   pcap_t *pcap_open_live(char *device,int snaplen, int prmisc,int to_ms,
	//	   char *ebuf)
	//
	//	   snaplen - maximum size of packets to capture in bytes
	//	   promisc - set card in promiscuous mode?
	//	   to_ms   - time to wait for packets in miliseconds before read
	//	   times out
	//	   errbuf  - if something happens, place error string here
	//
	//	   Note if you change "prmisc" param to anything other than zero, you will
	//	   get all packets your device sees, whether they are intendeed for you or
	//	   not!! Be sure you know the rules of the network you are running on
	//	   before you set your card in promiscuous mode!!

	//Put the device in sniff loop
	pcap_loop(handle , -1 , process_packet , NULL);

	pcap_close(handle);

	return 0;

}

void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *buffer)
{
//	printf("a packet is received! %d \n", total++);
	int size = header->len;
	//printf("%d\n",size);
	//Get the IP Header part of this packet , excluding the ethernet header
	struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
	++total;
	printf("%d\n",iph->protocol);
	if(iph->protocol==17) //Check the Protocol and do accordingly...
	{
		print_udp_packet(buffer , size);
		fflush(stdout);
	}
	

}

