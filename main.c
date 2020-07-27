#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>

#include "ethernet.h"
#include "verbose.h"

int n; // to number the packets

void packet_hdlr(u_char *args, const struct pcap_pkthdr *header,const u_char *body){
	struct ether_header *eth_header=NULL;
	int i,j;
	n++;
  if(*args & LOW)
		printf("\n#Num:%d: ", n);
	else if(*args & MID)
		printf("\n\n==Packet number %d :",n);
  else{
		printf("\n====================Packet number %d ====================\n",n);

		printf("\n\tPacket in HEX :\n");
		printf("\t----------------------------------\n\t|");
		for (i = 0; i < header->len ; ++i){
			  printf("%02x", body[i]);
				j++;
				if (j%16==0)
					printf("|\n\t|");
		}
		printf("\n\t----------------------------------\n");
	}
  //Start the analyze of the packet
	ethernet_analyze(eth_header,body,header,*args);

}

void usage(){
	printf("Hello !\nusage: ./projet\n\t-i <interface>\n\t-o <file>\n\t-f <filter>\n\t-v <1..3>\n");
}

int main(int argc, char *argv[])
{
	int verb, verbose = HIGH; // verbosity is high (by default)
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	bpf_u_int32 mask;  //For capture in interface
	bpf_u_int32 net;  //For capture in interface
  pcap_t *handle;
	char c;
	char *device = NULL;
	char *file = NULL;
  char *filter = NULL;

    //Options
	while((c = getopt(argc, argv, "i:o:f:v:u")) != -1) {
		switch(c) {
			case 'i':
				device = optarg;
				break;
			case 'o':
				file = optarg;
				break;
			case 'f':
				filter = optarg;
				break;
			case 'v':
				verb = atoi(optarg);
				if(verb >= 1 && verb <= 3)
					if(verb == 3)
						verbose = HIGH;
					else
						verbose = verb;
				else
					printf("You should choose a verbose between 1 and 3");
				break;
			case 'u':
			 	usage();
				return -1;
				break;
		}
	}

	// find the default device on which to capture
	if(device == NULL) {
		if ((device = pcap_lookupdev(errbuf)) == NULL) {
			fprintf(stderr, "Couldn't find default device\n");
			return -1;
		}
	}
  printf("Device: %s\n", device);

	//find the IPv4 network number and netmask for a device
	if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device %s\n", device);
	}

	if(file == NULL) {
		//open a device for capturing
		if ((handle = pcap_open_live(device, BUFSIZ, 1, 0, errbuf)) == NULL) {
			fprintf(stderr, "Couldn't open device %s\n", device);
			return -1;
		}
		// Parse and install filter
		if(filter != NULL) {
			if (pcap_compile(handle, &fp, filter, 0, net) == -1) {
				fprintf(stderr, "Couldn't parse filter %s\n", filter);
				return -1;
			}
			if (pcap_setfilter(handle, &fp) == -1) {
				fprintf(stderr, "Couldn't install filter %s\n", filter);
				return -1;
			}
		}
	}
	else {
		if ((handle = pcap_open_offline(file, errbuf)) == NULL) {
			fprintf(stderr, "Couldn't open the file %s\n", file);
			return -1;
		}
	}

  pcap_loop(handle, -1, packet_hdlr, (u_char*)&verbose);
	// End session
	pcap_close(handle);
	return 0;
}
