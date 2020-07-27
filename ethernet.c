#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include "network.h"
#include "verbose.h"

// Ethernet packet analyzer
void ethernet_analyze(struct ether_header *eth_header,const u_char *body,const struct pcap_pkthdr *header,u_char verbose){
	int i;
  int size=0;
  arp_hdr *arpheader = NULL;
	struct ip *iphdr = NULL;
	eth_header = (struct ether_header *) body; ;
	size+=sizeof(struct ether_header);

  if(verbose & (HIGH)) {
      printf("\n ***ETHERNET******************************************\n");
      printf("Destination host: ");
    	for(i=0; i<6;i++)
    			printf("%02x:", eth_header->ether_dhost[i]);

      printf("\nSource host: ");
    	for(i=0; i<6;i++)
    			printf("%02x:", eth_header->ether_shost[i]);
    	printf("\n");

      //Protocol type
    	if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    			printf("Type IPv4 (0x%04x)\n",ntohs(eth_header->ether_type));
          //Call the function that will analyze the next layer
    			iphdr_analyze(iphdr,body,size,  verbose);
    	} else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
    			printf("Type ARP (0x%04x)\n",ntohs(eth_header->ether_type));
    			arp_analyze(arpheader,body,size, verbose);
    	} else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
    			printf("Type IPv6 (0x%04x)\n",ntohs(eth_header->ether_type));
    	}
    	printf("\n");
  }
  //For verbose 1 and 2
  if(verbose & (LOW|MID)){
    	printf("(Ethernet)  ");
    	printf("Src :");
    	for(i=0; i<6;i++)
    			printf("%02x:", eth_header->ether_shost[i]);

      printf(" ,Dst:");
    	for(i=0; i<6;i++)
    			printf("%02x:", eth_header->ether_dhost[i]);
      if(verbose & MID){
        	printf("\n");
      }
    	if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
    			iphdr_analyze(iphdr,body,size,  verbose);
    	} else if (ntohs(eth_header->ether_type) == ETHERTYPE_ARP) {
    			arp_analyze(arpheader,body,size, verbose);
    	}
      else if (ntohs(eth_header->ether_type) == ETHERTYPE_IPV6) {
    			printf("Type IPv6 (0x%04x)\n",ntohs(eth_header->ether_type));
    	}
  }
}
