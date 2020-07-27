#include <sys/socket.h>   // pour inet_ntoa
#include <netinet/in.h>
#include <arpa/inet.h>

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "network.h"
#include "transport.h"
#include "verbose.h"
#include "sctp.h"

// IPv4 packet analyzer
void iphdr_analyze(struct ip *ip,const u_char *body, int size,u_char verbose){
	struct icmp * icmp=NULL;
  struct tcphdr * tcphdr = NULL;
  struct udphdr * udphdr = NULL;
  struct sctphdr * sctphdr = NULL;
	ip = (struct ip *) (body+size);
  int ip_size = 4*ip->ip_hl;  //IP Header lenght in bytes
  size+=sizeof(struct ip); //

  if(verbose & (HIGH)) {
      printf("\n ***********IP************************************\n");
      printf("Version: %d\n", ip->ip_v);
      printf("IHL : %d bytes \n", (ip->ip_hl)*4);
      printf("Type of service : 0x%02x\n", ip->ip_tos);
      printf("Total Lenght: %d\n", ntohs(ip->ip_len));
      printf("Identification: 0x%04x (%d)\n", ntohs(ip->ip_id), ntohs(ip->ip_id));
      //Flags
      printf("Flags: 0x%04x\t", ip->ip_off);
      if(ntohs(ip->ip_off) & IP_RF)
    			printf("Reserved bit  ");
    	if(ntohs(ip->ip_off) & IP_DF)
    			printf("Don't fragment ");
    	if(ntohs(ip->ip_off) & IP_MF)
    			printf("More fragment ");
      if(!(ntohs(ip->ip_off) & IP_RF) && !(ntohs(ip->ip_off) & IP_DF) && !(ntohs(ip->ip_off) & IP_MF))
          printf("Reserved bit & Don't fragment & More fragment not set");
      printf("\nTime to live: %d\n", ip->ip_ttl);
      printf("Protocol: ");
      switch(ip->ip_p) {
    			case 1:
    				printf("ICMP (%d) \n",ip->ip_p);
    				break;
    			case 6:
    				printf("TCP (%d)\n",ip->ip_p);
    				break;
    			case 17:
    				printf("UDP (%d)\n",ip->ip_p);
    				break;
          case 132:
      			printf("SCTP (%d)\n",ip->ip_p);
      			break;
    			default:
    				printf("Unknown \n");
    				break;
      }
      printf("Header Checksum: 0x%04x\n", ntohs(ip->ip_sum));
      printf("Source IP: %s\n",inet_ntoa( ip->ip_src));
      printf("Destination IP: %s\n", inet_ntoa(ip->ip_dst));
  }


  if(verbose & (LOW|MID)){
    printf("  (IPv4)");
    printf(" Src :%s",inet_ntoa( ip->ip_src));
    printf("  ,Dst:%s", inet_ntoa(ip->ip_dst));

  }

  if(verbose & (MID)){
    printf("  IHL : %d bytes", (ip->ip_hl)*4);
    printf("  Type of service : 0x%02x", ip->ip_tos);
    printf("  Total Lenght: %d\n", ntohs(ip->ip_len));
  }
  //Check the Protocol and call the function that will be responsible to
  //analyze the next layer
	switch (ip->ip_p){
			 case 1:
					 icmp_analyze( icmp,body,size,verbose);
					 break;
			 case 6:
           // "ntohs(ip->ip_len)-ip_size" represent the size from the
           //beginning of the ip layer until the end of the frame
					 tcp_analyze(tcphdr,body,size,ntohs(ip->ip_len)-ip_size,verbose);
					 break;
			 case 17:
					 udp_analyze(udphdr,body,size,verbose);
					 break;
       case 132:
           sctp_analyze(sctphdr,body,size,verbose);
           break;
			 default:
					 break;
	 }
}

// ARP packet analyzer
void arp_analyze(arp_hdr *arpheader,const u_char *body, int size,u_char verbose){
	int i;
  arpheader = (struct arp_hdr *)(body+size);
  if(verbose & (HIGH)) {
      printf("\n ***********ARP************************************\n");
    	printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet (1)" : "Unknown");
      printf("Protocol type: ");
    	switch(ntohs(arpheader->ptype)) {
    		case ETHERTYPE_IP:
  				printf("IPv4 (0x%04x)\n",ntohs(arpheader->ptype));
  				break;
      	case ETHERTYPE_IPV6:
    			printf("IPv6 (0x%04x)\n",ntohs(arpheader->ptype));
    			break;
    		default:
    			printf("Unknown\n");
    			break;
      }
    	printf("Hardware size: %d\n",arpheader->hlen);
      printf("Protocol size: %d\n",arpheader->plen);
      // ARP opcode (command)
      printf("Opcode : ");
      switch(ntohs(arpheader->oper)) {
    		case 1:
    			printf("ARP Request (%d)\n",ntohs(arpheader->oper));
    			break;
      	case 2:
      		printf("ARP Reply (%d)\n",ntohs(arpheader->oper));
      		break;
      	case 3:
      		printf("RARP Request (%d)\n",ntohs(arpheader->oper));
      	  break;
      	case 4:
      		printf("RARP Reply (%d)\n",ntohs(arpheader->oper));
      		break;
        case 8:
      		printf("InARP Request (%d)\n",ntohs(arpheader->oper));
      		break;
      	case 9:
      		printf("InARP Reply (%d)\n",ntohs(arpheader->oper));
      		break;
      	case 10:
      		printf("ARP NAK (%d)\n",ntohs(arpheader->oper));
      		break;
      	default:
      		printf("Unknown\n");
      		break;
      }

    	if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800){
    		printf("Sender MAC address: ");
    		for(i=0; i<6;i++)
    				printf("%02X:", arpheader->sha[i]);

    		printf("\nSender IP address: ");
    		for(i=0; i<4;i++)
    				printf("%d.", arpheader->spa[i]);

    		printf("\nTarget MAC address: ");
    		for(i=0; i<6;i++)
    				printf("%02X:", arpheader->tha[i]);

    		printf("\nTarget IP address: ");
    		for(i=0; i<4; i++)
    				printf("%d.", arpheader->tpa[i]);
    	}
    	printf("\n");
    }

    //For verbose 1 and 2
    if(verbose & (MID|LOW)) {
      printf(" (ARP) ");
      if(verbose & (MID)) {
        if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800){
      		printf("  Sender MAC address: ");
      		for(i=0; i<6;i++)
      				printf("%02X:", arpheader->sha[i]);

      		printf("  Sender IP address: ");
      		for(i=0; i<4;i++)
      				printf("%d.", arpheader->spa[i]);

      		printf("  Target MAC address: ");
      		for(i=0; i<6;i++)
      				printf("%02X:", arpheader->tha[i]);

      		printf("  Target IP address: ");
      		for(i=0; i<4; i++)
      				printf("%d.", arpheader->tpa[i]);
      	}
        printf("\t");
      }
      switch(ntohs(arpheader->oper)) {
        case 1:
          printf("ARP Request \n");
          break;
        case 2:
          printf("ARP Reply \n");
          break;
        case 3:
          printf("RARP Request\n");
          break;
        case 4:
          printf("RARP Reply");
          break;
        case 8:
          printf("InARP Request ");
          break;
        case 9:
          printf("InARP Reply ");
          break;
        case 10:
          printf("ARP NAK ");
          break;
        default:
          printf("Unknown\n");
          break;
      }
   }
}
