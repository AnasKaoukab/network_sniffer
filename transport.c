#include <pcap.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include "transport.h"
#include "application.h"
#include "verbose.h"
#include "sctp.h"

// ICMP packet analyzer
//si je veux ajouter les cas et voir le temps
void icmp_analyze(struct icmp * icmp, const u_char *body, int size, u_char verbose ){
  icmp = (struct icmp *) (body+size);
  if(verbose & (MID|LOW)){
    printf("\t(ICMP) \n");
  }

  if(verbose & (HIGH)){
    printf("\n ********************************ICMP***************\n");
  }

  if(verbose & (MID|HIGH)) {
      printf("Type :" );
      switch(icmp->icmp_type){
         case 0:
            printf("%d (Echo Reply)",icmp->icmp_type);
            break;
         case 3:
            printf("%d (Unreach)",icmp->icmp_type);
            break;
         case 5:
               printf("%d (Redirect)",icmp->icmp_type);
               break;
         case 8:
              printf("%d (Echo Request)",icmp->icmp_type);
              break;
          default:
              printf("Unknown");
              break;
      }
      printf("\n");
   }

   if(verbose & (HIGH)){
    	printf("Code: %d\n",icmp->icmp_code);
    	printf("Checksum 0x%04x\n",ntohs(icmp->icmp_cksum));
      printf("Identifier (BE): %d (0x%04x)\n",ntohs(icmp->icmp_id),ntohs(icmp->icmp_id));
      printf("Identifier (LE):%d (0x%04x)\n",icmp->icmp_id,icmp->icmp_id);
      printf("Sequence number (BE): %d (0x%04x)\n",ntohs(icmp->icmp_seq),ntohs(icmp->icmp_seq));
      printf("Sequence number (LE): %d (0x%04x)\n",icmp->icmp_seq,icmp->icmp_seq);
   }
}

// TCP packet analyzer
void tcp_analyze(struct tcphdr * tcp,const u_char *body, int size , int data_size, u_char verbose ){
  int vide=1;
  int i;
  tcp = (struct tcphdr *) (body+size);
  int tcp_size = tcp->th_off*4;  //TCP header lenght
  int size_h;
  size_h=size+sizeof(struct tcphdr); // The size from the begining of the frame until the tcp header
  size+=tcp_size; // The size from the beginnig of the frame until the end of the tcp layer

  if(verbose & (MID|LOW)){
    printf(" (TCP) ");
  }
  if(verbose & (MID|HIGH)) {
    if(verbose & (HIGH)) {
       printf("\n ********************************TCP***************\n");
  	   printf("Source port: %d\n", ntohs(tcp->th_sport));
  	   printf("Destination port: %d\n", ntohs(tcp->th_dport));
       printf("Sequence number: %u\n", ntohl(tcp->th_seq));
       printf("Acknowledgment number: %u\n", ntohl(tcp->th_ack));
    }
    //Flags
    printf("Flags: 0x%02x", tcp->th_flags);
    if(tcp->th_flags & TH_FIN)
      printf(" (FIN)");
    if(tcp->th_flags & TH_SYN )
      printf(" (SYN)");
    if(tcp->th_flags & TH_RST)
      printf(" (RST)");
    if(tcp->th_flags & TH_PUSH)
      printf(" (PSH)");
    if(tcp->th_flags & TH_ACK)
      printf(" (ACK)");
    if(tcp->th_flags & TH_URG)
      printf(" (URG)");
    if(verbose & (HIGH)) {
      printf("\n");
      printf("Window size value: %d\n", ntohs(tcp->th_win));
      printf("Checksum: 0x%04x\n", ntohs(tcp->th_sum));
    	printf("Urgent pointer: %d\n",ntohs(tcp->th_urp));
      //Option analysis
      printf("Options: (%li bytes) \n", tcp_size-sizeof(struct tcphdr));
    	for(i=size_h; i<size && body[i] != 0x00; i++) {
            printf("\t");
    				switch(body[i]) {
    					case 1:
    						printf("Kind: No-Operation (%d)\n", body[i]);
    						break;
    					case 2:
    						printf("Kind: maximum segment size (%d)\n", body[i]);
    						printf("\t\tLength: %d\n", body[i+1]);
    						printf("\t\tMSS value: %d\n", ntohs(*(u_int16_t*)(body + i + 2)));
    						i += (int)body[i+1]-1;
    						break;
    					case 3:
    						printf("Kind: windows scale (%d)\n", body[i]);
    						printf("\t\tLength: %d\n", body[i+1]);
    						printf("\t\tShift count: %d\n", body[i+2]);
    						i += (int)body[i+1]-1;
    						break;
    					case 4:
    						printf("Kind: SACK permited (%d)\n", body[i]);
    						printf("\t\tLength: %d\n", body[i+1]);
    						i += (int)body[i+1]-1;
    						break;
    					case 8:
    						printf("Kind: Timestamps(%d)\n", body[i]);
    						printf("\t\tLength: %d\n", body[i+1]);
    						printf("\t\tTimestamp value %u\n",ntohl(*(u_int32_t*)(body + i + 2)));
    						printf("\t\tTimestamp echo reply: %u\n", ntohl(*(u_int32_t*)(body + i + 6)));
    						i += (int)body[i+1]-1;
    						break;
    					default:
    						printf("Kind: Unknown (%d)\n", body[i]);
    						i += (int)body[i+1]-1;
    						break;
    				}
        }
      }
    }

    if(verbose & (MID|LOW)){
      printf("  Src port: %d   ", ntohs(tcp->th_sport));
    	printf(",Dst port: %d  ", ntohs(tcp->th_dport));
      printf(",Seq: %d  ", ntohl(tcp->th_seq));
      printf(",Ack: %d  ", ntohl(tcp->th_ack));
    }

    if(verbose & (MID)){
      printf("Window size value: %d  ", ntohs(tcp->th_win));
      printf("Checksum: 0x%04x  \n", ntohs(tcp->th_sum));
    }
    // Call the function that will analyze next layer depending on the port
    if ((data_size - tcp_size) >0 ){
      switch(ntohs(tcp->source)){
        case 20:
          ftp_analyze(body,size,(int)(data_size - tcp_size), verbose);
          vide=0;
          break;
        case 21:
          ftp_analyze(body,size,(int)(data_size - tcp_size), verbose);
          vide=0;
          break;
        case 23:
          telnet_analyze(body,size,(int)(data_size - tcp_size), verbose);
          vide=0;
          break;
       case 25:
          smtp_analyze(body,size,(int)(data_size - tcp_size), verbose);
          vide=0;
          break;
        case 80:
          http_analyze(body,size,(int)(data_size - tcp_size), verbose);
          vide=0;
          break;
        case 110:
          pop_analyze(body,size,(int)(data_size - tcp_size), verbose);
          vide=0;
          break;
        case 143:
          imap_analyze(body,size,(int)(data_size - tcp_size), verbose);
          vide=0;
          break;
      }
      // if we call the function that will analyze the next layer before (src port) we shouldn't
      //check for the dest port so as to avoid to analyze the next layer twice and to repeat the analysis
      if(vide == 1) {
        switch(ntohs(tcp->dest)){
          case 20:
            ftp_analyze(body,size,(int)(data_size - tcp_size), verbose);
            break;
          case 21:
            ftp_analyze(body,size,(int)(data_size - tcp_size), verbose);
            break;
          case 23:
            telnet_analyze(body,size,(int)(data_size - tcp_size), verbose);
            vide=0;
            break;
         case 25:
            smtp_analyze(body,size,(int)(data_size - tcp_size), verbose);
            break;
          case 80:
            http_analyze(body,size,(int)(data_size - tcp_size), verbose);
            break;
          case 110:
            pop_analyze(body,size,(int)(data_size - tcp_size), verbose);
            break;
          case 143:
            imap_analyze(body,size,(int)(data_size - tcp_size), verbose);
            break;
        }
      }
    }
    printf("\n");
}

// SCTP packet analyzer
void sctp_analyze(struct sctphdr * sctphdr,const u_char *body, int size, u_char verbose ){
  sctphdr = (struct sctphdr *) (body+size);
  size+=sizeof(struct sctphdr);
  u_int32_t *tsn, *adv, *payload_prot;
  u_int16_t *sid, *ssq;
  tsn = (u_int32_t*)(body + size); // to get cumulative TSN ack value
  adv = (u_int32_t*)(body + size+4); // to get the advertised receiver window credit value
  payload_prot = (u_int32_t*)(body + size+8); //to get the payload protocol identifier value
  sid = (u_int16_t*)(body + size+4); // to get the Stream identifier value
  ssq = (u_int16_t*)(body + size+6); // to get stream sequence number vaklue

  if(verbose & (MID|LOW)){
    printf(" (SCTP) ");
  }
  if(verbose & (HIGH)){
    printf("\n ********************************SCTP***************\n");
  }

  if(verbose & (HIGH)){
    printf("Source port: %d\n", ntohs(sctphdr->src_port));
    printf("Destination port: %d\n", ntohs(sctphdr->dest_port));
    printf("Verification tag: 0x%08x\n", ntohl(sctphdr->v_tag));
    printf("Checksum: 0x%08x\n", ntohl(sctphdr->checksum));
    //Type
    printf("Chunk type: ");
    switch(sctphdr->chunk_type) {
        case 14:
          printf("SHUTDOWN_COMPLETE (%d) \n",sctphdr->chunk_type);
          break;
        case 8:
          printf("SHUTDOWN_ACK (%d)\n",sctphdr->chunk_type);
          break;
        case 7:
          printf("SHUTDOWN (%d)\n",sctphdr->chunk_type);
          printf("Cumulative TSN Ack %u\n",ntohl(*tsn));
          break;
        case 3:
          printf("SACK (%d)\n",sctphdr->chunk_type);
          printf("Cumulative TSN Ack %u\n",ntohl(*tsn));
          printf("Advertised receiver window credit %u\n",ntohl(*adv));
          break;
        case 0:
          printf("DATA (%d)\n",sctphdr->chunk_type);
          printf("Transmission sequence number %u\n",ntohl(*tsn));
          printf("Stream identifier 0x%04x\n",ntohs(*sid));
          printf("Stream sequence number %d\n",ntohs(*ssq));
          printf("Payload protocol identifier %u\n",ntohl(*payload_prot));
          break;
        case 11:
          printf("COOKIE_ACK (%d)\n",sctphdr->chunk_type);
          break;
        case 10:
          printf("COOKIE_ECHO (%d)\n",sctphdr->chunk_type);
          break;
        case 1:
          printf("INIT (%d)\n",sctphdr->chunk_type);
          printf("Initiate tag 0x%08x\n",ntohl(*tsn));
          printf("Advertised receiver window credit %u\n",ntohl(*adv));
          printf("Number of outbound streams %d\n",ntohs(*(u_int16_t*)(body + size + 8)));
          printf("Number of outbound streams %d\n",ntohs(*(u_int16_t*)(body + size + 10)));
          printf("Initial TSN %u\n",ntohl(*(u_int32_t*)(body + size + 12)));
          printf("Parameter type  0x%04x\n",ntohs(*(u_int16_t*)(body + size + 16)));
          printf("Parameter Lenght %d \n",ntohs(*(u_int16_t*)(body + size + 18)));
          printf("Supported address type (%d)",ntohs(*(u_int16_t*)(body + size + 20)));
          if ((ntohs(*(u_int16_t*)(body + size + 20)))==5)
            printf("Ipv4 Address\n");
          else if ((ntohs(*(u_int16_t*)(body + size + 20)))==6)
            printf("Ipv6 Address\n");
          else
            printf("Unknown\n");
          printf("Parameter Padding %d\n",ntohs(*(u_int16_t*)(body + size + 22)));
          break;
        case 2:
          printf("INIT_ACK (%d)\n",sctphdr->chunk_type);
          printf("Initiate tag 0x%08x\n",ntohl(*tsn));
          printf("Advertised receiver window credit %u\n",ntohl(*adv));
          printf("Number of outbound streams %d\n",ntohs(*(u_int16_t*)(body + size + 8)));
          printf("Number of outbound streams %d\n",ntohs(*(u_int16_t*)(body + size + 10)));
          printf("Initial TSN %u\n",ntohl(*(u_int32_t*)(body + size + 12)));
          printf("Parameter type  0x%04x\n",ntohs(*(u_int16_t*)(body + size + 16)));
          printf("Parameter Lenght %d \n",ntohs(*(u_int16_t*)(body + size + 18)));
          break;
        case 6:
          printf("ABORT (%d)\n",sctphdr->chunk_type);
          break;
        default:
          printf("Unknown \n");
          break;
      }
      printf("Chunk flags: 0x%02x\n", ntohs(sctphdr->chunk_flags));
      printf("Chunk length: %d\n", ntohs(sctphdr->chunk_length));
    }

    if(verbose & (LOW|MID)) {
        printf("  Source port: %d", ntohs(sctphdr->src_port));
        printf("  Destination port: %d", ntohs(sctphdr->dest_port));
        if(verbose & (MID)) {
          printf("  Verification tag: 0x%08x", ntohl(sctphdr->v_tag));
          printf("  Checksum: 0x%08x  ", ntohl(sctphdr->checksum));
          switch(sctphdr->chunk_type) {
              case 14:
                printf("SHUTDOWN_COMPLETE (%d) \n",sctphdr->chunk_type);
                break;
              case 8:
                printf("SHUTDOWN_ACK (%d)\n",sctphdr->chunk_type);
                break;
              case 7:
                printf("SHUTDOWN (%d)\n",sctphdr->chunk_type);
                break;
              case 3:
                printf("SACK (%d)\n",sctphdr->chunk_type);
                break;
              case 0:
                printf("DATA (%d)\n",sctphdr->chunk_type);
                break;
              case 11:
                printf("COOKIE_ACK (%d)\n",sctphdr->chunk_type);
                break;
              case 10:
                printf("COOKIE_ECHO (%d)\n",sctphdr->chunk_type);
                break;
              case 1:
                printf("INIT (%d)\n",sctphdr->chunk_type);
                break;
              case 2:
                printf("INIT_ACK (%d)\n",sctphdr->chunk_type);
                break;
              case 6:
                printf("ABORT (%d)\n",sctphdr->chunk_type);
                break;
              default:
                printf("Unknown \n");
                break;
            }
        }
        printf("\n");
    }

}

// UDP packet analyzer
void udp_analyze(struct udphdr * udphdr,const u_char *body, int size, u_char verbose ){
  int vide=1;
  struct dnshdr *dnshdr =NULL;
  struct bootphdr *bootphdr =NULL;
  udphdr = (struct udphdr *) (body+size);
  size+=sizeof(struct udphdr);
  if(verbose & (HIGH)) {
    printf("\n ********************************UDP***************\n");
    printf("Source port: %d\n", ntohs(udphdr->uh_sport));
    printf("Destination port: %d\n", ntohs(udphdr->uh_dport));
    printf("Lenght: %d\n", ntohs(udphdr->uh_ulen));
    printf("Checksum: 0x%02x\n", ntohs(udphdr->uh_sum));
  }
  if(verbose & (MID|LOW)){
    printf("   (UDP) ");
    printf("Src port: %d  ", ntohs(udphdr->uh_sport));
    printf(",Dst port: %d  ", ntohs(udphdr->uh_dport));
  }
  if(verbose & (MID)){
    printf("Lenght: %d  ", ntohs(udphdr->uh_ulen));
    printf("Checksum: 0x%02x\n", ntohs(udphdr->uh_sum));
  }
  // Call the function that will analyze next layer depending on the port
  switch (ntohs(udphdr->uh_sport)){
			 case 53:
					 dns_analyze( dnshdr,body,size,(int)(ntohs(udphdr->uh_ulen) - sizeof(struct udphdr)), verbose);
           vide=0;
           break;
			 case 67:
					 bootp_analyze(bootphdr,body,size,(int)(ntohs(udphdr->uh_ulen) - sizeof(struct udphdr)), verbose);
           vide=0;
           break;
			 case 68:
					 bootp_analyze(bootphdr,body,size,(int)(ntohs(udphdr->uh_ulen) - sizeof(struct udphdr)), verbose);
           vide=0;
           break;
			 default:
					 break;
	}

  if(vide == 1) {
   switch (ntohs(udphdr->uh_dport)){
     	 case 53:
            dns_analyze( dnshdr,body,size,(int)(ntohs(udphdr->uh_ulen) - sizeof(struct udphdr)), verbose);
            break;
        case 67:
            bootp_analyze(bootphdr,body,size,(int)(ntohs(udphdr->uh_ulen) - sizeof(struct udphdr)), verbose);
            break;
        case 68:
            bootp_analyze(bootphdr,body,size,(int)(ntohs(udphdr->uh_ulen) - sizeof(struct udphdr)), verbose);
            break;
        default:
            break;
    }
  }
}
