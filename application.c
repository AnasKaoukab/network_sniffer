#include <sys/socket.h>   // pour inet_ntoa
#include <netinet/in.h>
 #include <arpa/inet.h>

#include <pcap.h>
#include <netinet/in.h>
#include <ctype.h>
#include "verbose.h"
#include "application.h"

// TELNET packet analyzer
void telnet_analyze( const u_char *body, int size,int data_size,u_char verbose ){
  int i = size;
  int init=1; //pour l'affichage
  if(verbose & (MID|LOW)){
    printf(" (TELNET) ");
  }
  if(verbose & (HIGH)){
    printf("\n ***********************************************TELNET\n");
  }
  if(verbose & (HIGH)) {
  	while(i < data_size+size){
  		if(body[i] == 255) {
  			i++;
  			while(body[i]!=255 && i < data_size+size){
  				switch(body[i]) {
  						case 0:
  							printf("\n\tSubcommand:  transmission ");
  							break;
                case 1:
                  printf("\n\tSubcommand: Echo ");
                  break;
                case 2:
                  printf("\n\tSubcommand: Reconnection ");
                  break;
                case 3:
                  printf("\n\tSubcommand: Suppress go ahead ");
                  break;
                case 4:
                  printf("\n\tSubcommand: Approx message size negotation ");
                  break;
                case 5:
                  printf("\n\tSubcommand: Status ");
                  break;
                case 6:
                  printf("\n\tSubcommand: Timing mark ");
                  break;
                case 7:
                  printf("\n\tSubcommand: Remote controlled transmition and echo");
                  break;
                case 8:
                  printf("\n\tSubcommand: Backspace ");
                  break;
                case 9:
                  printf("\n\tSubcommand: Horizontal Tab ");
                  break;
                case 10:
                  printf("\n\tSubcommand: Line Feed ");
                  break;
                case 11:
                  printf("\n\tSubcommand: Vertical Tab");
                  break;
                case 12:
                  printf("\n\tSubcommand: Form Feed ");
                  break;
                case 13:
                  printf("\n\tSubcommand: Carriage Return ");
                  break;
                case 14:
                  printf("\n\tSubcommand: Output vertical tabstops ");
                  break;
                case 15:
                  printf("\n\tSubcommand: Output vertical tab disposition ");
                  break;
                case 16:
                  printf("\n\tSubcommand: Output linefeed disposition ");
                  break;
                case 17:
                  printf("\n\tSubcommand: Extended ASCII ");
                  break;
                case 18:
                  printf("\n\tSubcommand: Logout ");
                  break;
                case 19:
                  printf("\n\tSubcommand: Byte macro ");
                  break;
                case 20:
                  printf("\n\tSubcommand: Data entry terminal ");
                  break;
                case 21:
                  printf("\n\tSubcommand: SUPDUP ");
                  break;
                case 22:
                  printf("\n\tSubcommand: SUPDUP output ");
                  break;
                case 23:
                  printf("\n\tSubcommand: Send location ");
                  break;
                case 24:
                  printf("\n\tSubcommand: Terminal type ");
                  break;
                case 25:
                  printf("\n\tSubcommand: End of record ");
                  break;
                case 26:
                  printf("\n\tSubcommand: TACACS user identification ");
                  break;
                case 27:
                  printf("\n\tSubcommand: Output marking");
                  break;
                case 28:
                  printf("\n\tSubcommand: Terminal location number ");
                  break;
                case 29:
                  printf("\n\tSubcommand: Telnet 3270 regime ");
                  break;
                case 30:
                  printf("\n\tSubcommand: X.3 PAD ");
                  break;
                case 31:
                  printf("\n\tSubcommand: Window size ");
                  break;
                case 32:
                  printf("\n\tSubcommand: Terminal speed ");
                  break;
                case 33:
                  printf("\n\tSubcommand: Remote flow control ");
                  break;
                case 34:
                  printf("\n\tSubcommand: Linemode ");
                  break;
                case 35:
                  printf("\n\tSubcommand: X display location");
                  break;
                case 36:
                  printf("\n\tSubcommand: Environment option ");
                  break;
                case 38:
                  printf("\n\tSubcommand: Encryption option ");
                  break;
                case 39:
                  printf("\n\tSubcommand: New environment option ");
                  break;
                case 240:
                  printf("Command :Suboption End (%d)",body[i]);
                  break;
                case 241:
                  printf("Command :No Operation (%d)",body[i]);
                  break;
                case 242:
                  printf("Command :Data Mark (%d)",body[i]);
                  break;
                case 244:
                  printf("Command :Intrerrupt Process(%d)",body[i]);
                  break;
                case 245:
                  printf("Command :Abort Output (%d)",body[i]);
                  break;
                case 246:
                  printf("Command :Are You There (%d)",body[i]);
                  break;
                case 247:
                  printf("Command :Erase Character (%d)",body[i]);
                  break;
                case 248:
                  printf("Command :Erase Line (%d)",body[i]);
                  break;
                case 249:
                  printf("Command :Go Ahead (%d)",body[i]);
                  break;
                case 250:
                  printf("Command :Suboption (%d)",body[i]);
                  break;
                case 251:
                  printf("Command :WILL (%d)",body[i]);
                  break;
                case 252:
                  printf("Command :WON'T (%d)",body[i]);
                  break;
                case 253:
                  printf("Command :DO (%d)",body[i]);
                  break;
                case 254:
                  printf("Command :DON'T (%d)",body[i]);
                  break;
  						default:
  							  printf("%c", body[i]);
  							break;
  					}
  					i++;
  				}
          printf("\n");
  			}

        else {
            if (init==1){
              printf("Data : ");
              init=0;
            }
            if(body[i-1] == '\n')
              printf("\nData : ");
  				printf("%c", body[i]);
  				i++;
  			}
  		}
  		printf("\n");
  	}
}


// IMAP packet analyzer
void imap_analyze( const u_char *body, int size,int data_size,u_char verbose ){
  int i;
  if(verbose & (MID|LOW)){
    printf(" (IMAP)");
  }

  if(verbose & (HIGH)){
    printf("\n ***********************************************IMAP\n");
  }

  if(verbose & (HIGH)) {
		printf("Ligne : ");
    for (i = size; i < size+data_size; ++i){
    if(body[i-1] == '\n')
      printf("\nLine : ");
    if(isprint(body[i]) || body[i] == '\t' || body[i] == '\r')
      printf("%c", body[i]);
    }
  }
}

// SMTP packet analyzer
void smtp_analyze( const u_char *body, int size,int data_size, u_char verbose ){
  int i;
  if(verbose & (MID|LOW)){
    printf(" (SMTP)");
  }
  if(verbose & (HIGH)){
    printf("\n ***********************************************SMTP\n");
  }
  if(verbose & (HIGH)) {
		for (i = size; i < size+data_size; ++i){
      //To manage typing special caracters
			if(isprint(body[i]) || body[i] == '\n' || body[i] == '\t' || body[i] == '\r')
				printf("%c", body[i]);
			else
				printf(".");
		}
  }
}

// POP packet analyzer
void pop_analyze( const u_char *body, int size,int data_size, u_char verbose ){
  int i;
  if(verbose & (MID|LOW)){
    printf(" (POP)\n");
  }
  if(verbose & (HIGH)){
    printf("\n ***********************************************POP\n");
  }
  if(verbose & (HIGH)) {
		for (i = size; i < size+data_size; ++i){
			if(isprint(body[i]) || body[i] == '\n' || body[i] == '\t' || body[i] == '\r')
				printf("%c", body[i]);
			else
				printf(".");
		}
  }
}

// FTP packet analyzer
void ftp_analyze( const u_char *body, int size,int data_size, u_char verbose ){
  int i;
  if(verbose & (MID|LOW)){
    printf(" (FTP)");
  }
  if(verbose & (HIGH)){
    printf("\n ***********************************************FTP\n");
  }
  if(verbose & (HIGH)) {
		for (i = size; i < size+data_size; ++i){
			if(body[i-1] == '\n')
				printf("\t\t\t");
			if(isprint(body[i]) || body[i] == '\n' || body[i] == '\t' || body[i] == '\r')
				printf("%c", body[i]);
			else
				printf(".");
		}
  }
}

// HTTP packet analyzer
void http_analyze( const u_char *body, int size,int data_size, u_char verbose ){
  int i;
  if(verbose & (MID|LOW)){
    printf(" (HTTP)");
  }
  if(verbose & (HIGH)){
    printf("\n ***********************************************HTTP\n");
  }
  if(verbose & (HIGH)) {
  		for (i = size; i < size+data_size; ++i){
        // Managing the typing of special caractere
  			if(isprint(body[i]) || body[i] == '\n' || body[i] == '\t' || body[i] == '\r')
  				printf("%c", body[i]);
  			else
  				printf(".");
  		}
  }
}

// BOOTP packet analyzer
void bootp_analyze(struct bootphdr * bootp, const u_char *body, int size,int data_size, u_char verbose ){
  int i,j,l,heure,min,sec;
	u_int32_t tmp;
  bootp = (struct bootphdr *) (body+size);
  if(verbose & (MID)){
    printf(" (BOOTP)");
  }
  if(verbose & (HIGH)){
    printf("\n ***********************************************BOOTP\n");
  }
  if(verbose & (MID|HIGH)) {
      switch(bootp->msg_type) {
    			case 1:
    				printf("Message type : Boot Request (%i) ",bootp->msg_type);
    				break;
    			case 2:
    				printf("Message type : Boot Reply (%i) ",bootp->msg_type);
    				break;
    			default:
    				printf("Message type : Unknown (%i) ",bootp->msg_type);
    				break;
    	}
      if(verbose & (HIGH))
        printf("\n ");

      printf("Hardware type : ");
    	switch(bootp->hrdwr_type) {
    			case 1:
    				printf("Ethernet (0x%02x) ",bootp->hrdwr_type);
    				break;
    			case 6:
    				printf("IEEE 802 (0x%02x) ",bootp->hrdwr_type);
    				break;
    			case 18:
    				printf("Fibre channel (0x%02x) ",bootp->hrdwr_type);
    				break;
    			case 20:
    				printf("Serial line (0x%02x) ",bootp->hrdwr_type);
    				break;
    			default:
    				printf("Unknown (0x%02x) ",bootp->hrdwr_type);;
    				break;
    	}
      if(verbose & (HIGH)){
        printf("\n ");
      	printf("Hardware address length : %d bytes\n", bootp->hrdwr_addr_length);
      	printf("Hops : %d\n", bootp->hops);
      	printf("Transaction ID : 0x%08x\n", ntohl(bootp->trans_id));
      	printf("Seconds elapsed : %d\n", ntohs(bootp->num_sec));
        printf("Bootp flags : 0x%04x\n", bootp->flags);
        printf("Client IP address : %s\n", inet_ntoa(bootp->ciaddr));
      	printf("Your (client) IP address : %s\n", inet_ntoa(bootp->yiaddr));
      	printf("Next server IP address : %s\n", inet_ntoa(bootp->siaddr));
      	printf("Relay agent IP address : %s\n", inet_ntoa(bootp->giaddr));

      	if(bootp->hrdwr_addr_length == 6) {
      			printf("Client MAC address : %02x:%02x:%02x:%02x:%02x:%02x\n",
      				bootp->hrdwr_caddr[0],bootp->hrdwr_caddr[1],bootp->hrdwr_caddr[2],
              bootp->hrdwr_caddr[3],bootp->hrdwr_caddr[4],bootp->hrdwr_caddr[5]);
              printf("Client hardware address padding : ");
      				for(i=6; i<16;i++) {
      					printf("%02x", bootp->hrdwr_caddr[i]);
              }
              printf("\n");
        }
        else {
      			 printf("Client hardware address unknown : ");
      			 for(i=0; i<16; i++) {
      			  	printf("%02x", bootp->hrdwr_caddr[i]);
      			 }
      			 printf("\n");
      	}

        printf("Server host name : ");
      	if(bootp->srv_name[0] != 0) {
      			for(i=0; i<64 && bootp->srv_name[i] != 0; i++) {
      					printf("%c", bootp->srv_name[i]);
      			}
      			printf("\n");
      	}
      	else {
      			printf("not given\n");
      	}

      	printf("Boot file name : ");
      	if(bootp->bpfile_name[0] != 0) {
      			for(i=0; i<128 && bootp->bpfile_name[i] != 0; i++) {
      					printf("%c", bootp->bpfile_name[i]);
      			}
      			printf("\n");
      	}
      	else {
      			printf("not given\n");
      	}
        // DHCP Analysis
        if(ntohl(bootp->magic_cookie) == 0x63825363){
            printf("Magic cookie : DHCP\n");
            for(i = sizeof(struct bootphdr)+size; i < (data_size+size) && body[i] != 255; i++) {
              printf("Option: (%i) ",(int)body[i]);
      				switch((int)body[i]) {
                case 1:
                  printf("Subnet mask ");
      						i++;
      						l = (int)body[i];
      						i++;
      						printf("%d.%d.%d.%d",body[i],body[i+1],body[i+2],body[i+3]);
                  printf("\n\tlenght %i\n",l);
      						i+=l-1;
      						break;
                case 50:
                  printf("Requested IP address ");
                  i++;
                  l = (int)body[i];
                  i++;
                  printf("%d.%d.%d.%d",body[i],body[i+1],body[i+2],body[i+3]);
                  printf("\n\tlenght %i\n",l);
                  i+=l-1;
                  break;
                case 51:
                  i++;
                  l = (int)body[i];
                  i++;
                  tmp = ntohl(*(u_int32_t*)(body + i ));;
                  heure=tmp/3600;
                  min=(tmp-heure*3600)/60;
                  sec=(tmp-heure*3600)%60;
                  printf("IP address lease time (%ds) %i hours ,%i minutes, %i seconds ",tmp , heure,min,sec);
                  printf("\n\tlenght %i\n",l);
                  i+=l-1;
                  break;
      					case 53:
      						printf("DHCP message type ");
      						i++;
      						l = (int)body[i];
      						i++;
      						switch((int)body[i]) {
      							case 1:
      								printf("(DISCOVER)");
      								break;
      							case 2:
      								printf("(OFFER)");
      								break;
      							case 3:
      								printf("(REQUEST)");
      								break;
      							case 4:
      								printf("(DECLINE)");
      								break;
      							case 5:
      								printf("(ACK)");
      								break;
      							case 6:
      								printf("(NACK)");
      								break;
      							case 7:
      								printf("(RELEASE)");
      								break;
      							default:
      								printf("(UNKNOWN)");
      								break;
      						}
                  printf("\n\tlenght %i\n",l);
      						i+=l-1;
      						break;
                 case 54:
        						i++;
        						l = (int)body[i];
        						i++;
                    printf("DHCP server identifier ");
        						printf("%d.%d.%d.%d",body[i],body[i+1],body[i+2],body[i+3]);
                    printf("\n\tlenght %i\n",l);
        						i+=l-1;
        						break;
        					case 55:
                    printf("Parameter Request List \n");
        						i++;
                    l=(int)body[i];
        						for(j=0;j<(int)body[i];j++) {
                      printf("\tParameter Request List Item: (%i)",body[i+j+1]);
        							switch(body[i+j+1]) {
        								case 1:
        									printf(" Subnet Mask");
        									break;
        								case 3:
        									printf(" Router");
        									break;
        								case 6:
        									printf(" Domain Name Server");
        									break;
        								case 42:
        									printf(" Network Time Protocol Servers");
        									break;
        								default:
        									printf(" Unknown");
        									break;
        							}
                      printf("\n");
        						}
        						i+=((int)body[i]);
        						printf("\tlenght %i\n",l);
        						break;
      					 case 58:
      						i++;
      						l = (int)body[i];
      						i++;
      						tmp = ntohl(*(u_int32_t*)(body + i ));
                  heure=tmp/3600;
                  min=(tmp-heure*3600)/60;
                  sec=(tmp-heure*3600)%60;
                  printf("Renewal Time Value (%ds) %i hours ,%i minutes, %i seconds ",tmp , heure,min,sec);
      						i+=l-1;
                  printf("\n\tlenght %i\n",l);
      						break;
      					case 59:
      						i++;
      						l = (int)body[i];
      						i++;
      						tmp = ntohl(*(u_int32_t*)(body + i ));
                  heure=tmp/3600;
                  min=(tmp-heure*3600)/60;
                  sec=(tmp-heure*3600)%60;
                  printf("Rebinding Time Value (%ds) %i hours ,%i minutes, %i seconds ",tmp , heure,min,sec);
      						i+=l-1;
                  printf("\n\tlenght %i\n",l);
      						break;
      					case 61:
      						i++;
      						l = (int)body[i];
      						i++;
                  printf("Hardware type 0x%02x\n", body[i]);
      						if((int)body[i] == 1) {
      							printf("\tClient identifier  %02x:%02x:%02x:%02x:%02x:%02x",
      								body[i+1],body[i+2],body[i+3],
      								body[i+4],body[i+5],body[i+6]);
      						}
      						else {
      							printf("unknown identifier");
      						}
                  printf("\n\tlenght %i\n",l);
      						i += l-1;
      						break;
      					default:
      						printf("Unknown (0x%02x)\n", body[i]);
      						i++;
      						printf("\t\t\t\tLength : %d bytes\n", (int)body[i]);
      						printf("\t\t\t\tValue : 0x");
      						for(j=0; j<(int)body[i];j++) {
      							printf("%02x", body[i+j+1]);
      						}
      						printf("\n");
      						i+=j;
      						break;
      				}

              if(body[i+1]==255) {
                printf("Option :(255) End");
              }
      			}
      		}
      }
    }

    //Verbose 1 and 2
    if(verbose & (LOW|MID)){
      if(verbose & (LOW))
        printf(" (BOOTP)");
      {
      			for(i = sizeof(struct bootphdr)+size; i < (data_size+size) && body[i] != 0xff; i++) {
      				switch((int)body[i]) {
      					case 53:
      						printf("(DHCP) ");
      						i++;
      						l = (int)body[i];
      						i++;
      						switch((int)body[i]) {
      							case 1:
      								printf("Discover");
      								break;
      							case 2:
      								printf("Offer");
      								break;
      							case 3:
      								printf("Request");
      								break;
      							case 4:
      								printf("Decline");
      								break;
      							case 5:
      								printf("Ack");
      								break;
      							case 6:
      								printf("Nack");
      								break;
      							case 7:
      								printf("release");
      								break;
      							default:
      								printf("Unknown");
      								break;
      						}
      						i+=l-1;
      						break;
      					default:
      						i++;
      						l = (int)body[i];
      						i+=l-1;
      						break;
      				}
      			}
      		}
          printf("\n");
    }
}

void dns_analyze(struct dnshdr * dnshdr,const u_char *packet, int size,int data_size, u_char verbose ){
  int i, j = 0, k,l=0, questions, answers;
  u_int16_t *type, *class, *d_size;
  u_int32_t *ttl;
  dnshdr = (struct dnshdr *) (packet+size);
  questions = ntohs(dnshdr->quest_count); // number of queries
  answers = ntohs(dnshdr->answ_count); //number of answers
  if(verbose & (MID)){
    printf(" (DNS)");
  }
  if(verbose & (HIGH)){
    printf("\n ***********************************************DNS\n");
  }
  if(verbose & (MID|HIGH)) {
      if(verbose & (HIGH)) {
          printf("Transaction id : 0x%04x\n", ntohs(dnshdr->query_id));
        	printf("Flags : 0x%04x\n", ntohs(dnshdr->flags));
          printf("Questions : %d\n", ntohs(dnshdr->quest_count));
          printf("Answer RRs : %d\n", ntohs(dnshdr->answ_count));
        	printf("Authority RRs : %d\n", ntohs(dnshdr->auth_count));
        	printf("Additional RRs : %d\n", ntohs(dnshdr->add_count));
      }
      if(questions > 0) {
          if(verbose & (HIGH))
    			     printf("\t\t\tQueries\n");
          if(verbose & (MID))
               printf("||Queries  ");
          l=j;
    			for(k = 0; k < questions; k++) {
            printf("Name: ");
    				for(i = sizeof(struct dnshdr)+ size + j; i < data_size+size && packet[i] != 0x00; i++) {
    						if(isprint(packet[i]))
    							printf("%c", packet[i]);
    						else
    							printf(".");
    				}

            if(verbose & (HIGH))
      			     printf("\n");
            printf(" [Name lenght]: %li   ",i-size-j-sizeof(struct dnshdr));
    				j = i+1;
            if(verbose & (HIGH))
      			     printf("\n");

            type = (u_int16_t*)(packet + j); // to get the type's value
    				j+=2;
    				class = (u_int16_t*)(packet + j); // to get the class's value
            switch(ntohs(*type)) {
                case 1:
                  printf("Type :A (Address record) (%i) ",ntohs(*type));
                  break;
                case 2:
                  printf("Type :NS (Authorative Name Server)(%i) ",ntohs(*type));
                  break;
                case 28:
                  printf("Type :AAAA (IPv6 address record) (%i) ",ntohs(*type));
                  break;
                case 5:
                  printf("Type :CNAME (Canonical name record) (%i) ",ntohs(*type));
                  break;
                case 12:
                  printf("Type :PTR (domain name PoinTeR)(%i) ",ntohs(*type));
                  break;
                case 15:
                  printf("Type :MX (Mail eXchange )(%i) ",ntohs(*type));
                  break;
                case 6:
                  printf("Type :SOA (Start of authority record)(%i) ",ntohs(*type));
                  break;
                case 16:
                  printf("Type :TXT (Text Strings)(%i) ",ntohs(*type));
                  break;
                case 33:
                  printf("Type :SRV (Server Selection)(%i) ",ntohs(*type));
                  break;
                default:
                  printf("Type :Unknown ");
                  break;
            }
            if(verbose & (HIGH))
      			     printf("\n");

            printf("Class : ");
            switch(ntohs(*class)) {
                case 0:
                  printf("Reserved (0x%04x) ",ntohs(*class));
                  break;
                case 1:
                  printf("IN (0x%04x) ",ntohs(*class));
                  break;
                case 2:
                  printf("Unassigned (0x%04x) ",ntohs(*class));
                  break;
                case 3:
                  printf("Chaos (0x%04x) ",ntohs(*class));
                  break;
                case 4:
                  printf("Hesiod(0x%04x) ",ntohs(*class));
                  break;
                default:
                  printf("Unknown(0x%04x) ",ntohs(*class));
                  break;
            }
            if(verbose & (HIGH))
      			     printf("\n");
          }
        }

        if(answers > 0) {

          if(verbose & (HIGH)){
    			   printf("\t\t\tAnswers\n");
             printf("Name: ");
     				for(i = sizeof(struct dnshdr)+ size + l; i < data_size+size && packet[i] != 0x00; i++) {
     					if(packet[i] == 0x03)
     						printf(".");
     					else if(packet[i] != 0x0c) {
     						if(isprint(packet[i]))
     							printf("%c", packet[i]);
     						else
     							printf(".");
     					}
     				}
            printf("\n");
          }
          if(verbose & (MID))
             printf("||Answers  ");

    			for(k = 0; k < answers; k++) {
    				j += 4;
    				type = (u_int16_t*)(packet + j);
    				j += 2;
    				class = (u_int16_t*)(packet + j);
    				j += 2;
    				ttl = (u_int32_t*)(packet + j);
    				j += 4;
    				d_size = (u_int16_t*)(packet + j);
    				j += 2;
            switch(ntohs(*type)) {
              case 1:
                printf("Type :A (Address record) (%i) ",ntohs(*type));
                break;
              case 28:
                printf("Type :AAAA (IPv6 address record) (%i) ",ntohs(*type));
                break;
              case 5:
                printf("Type :CNAME (Canonical name record) (%i) ",ntohs(*type));
                break;
              case 12:
                printf("Type :PTR (domain name PoinTeR) (%i) ",ntohs(*type));
                break;
              case 15:
                printf("Type :MX (Mail exchange record)(%i) ",ntohs(*type));
                break;
              case 2:
                printf("Type :NS (Authorative Name Server)(%i) ",ntohs(*type));
                break;
              case 6:
                printf("Type :SOA (Start of authority record)(%i) ",ntohs(*type));
                break;
              case 16:
                printf("Type :TXT (Text record)(%i) ",ntohs(*type));
                break;
              default:
                printf("Type :Unknown ");
                break;
            }
            if(verbose & (HIGH))
      			     printf("\n");

            switch(ntohs(*class)) {
                case 0:
                  printf("Class :Reserved (0x%04x) ",ntohs(*class));
                  break;
                case 1:
                  printf("Class :IN (0x%04x) ",ntohs(*class));
                  break;
                case 2:
                  printf("Class :Unassigned (0x%04x) ",ntohs(*class));
                  break;
                case 3:
                  printf("Class :Chaos (0x%04x) ",ntohs(*class));
                  break;
                case 4:
                  printf("Class :Hesiod(0x%04x) ",ntohs(*class));
                  break;
                default:
                  printf("Class :Unknown(0x%04x) ",ntohs(*class));
                  break;
            }
            if(verbose & (HIGH)) {
      			    printf("\n");
                printf("Time to live %d\n", ntohl(*ttl));
            	  printf("Data length %d\n", ntohs(*d_size));
                if(ntohs(*type) == 1) {
            				printf("Address%d.%d.%d.%d\n",packet[j],packet[j+1],packet[j+2],packet[j+3]);
            		}
                if(ntohs(*type) == 28) {
                    printf("Address %02x:%02x:%02x:%02x:%02x:%02x:%02x:%02x\n",
                    ntohs(*(u_int16_t*)(packet + j)),
                    ntohs(*(u_int16_t*)(packet + j+2)),
                    ntohs(*(u_int16_t*)(packet + j+4)),
                    ntohs(*(u_int16_t*)(packet + j+6)),
                    ntohs(*(u_int16_t*)(packet + j+8)),
                    ntohs(*(u_int16_t*)(packet + j+10)),
                    ntohs(*(u_int16_t*)(packet + j+12)),
                    ntohs(*(u_int16_t*)(packet + j+14)));
                  }
        	 		  else {
        					for(i = 0; i < ntohs(*d_size); ++i){
                    if(isprint(packet[j+i]))
                      printf("%c", packet[j+i]);
                    else
                      printf(".");
        					}
                  printf("\n");
         	      }
                j = j+ntohs(*d_size)-2;
          }
       }

       if(verbose & (HIGH))
          printf("\n");
      }
    }

    if(verbose & (LOW)){
      printf(" (DNS)  ");
      if(answers > 0 && questions>0)
    			printf("Query & Response");

      else if(questions > 0) {
    			printf("Query");
      }
      else if(answers > 0) {
    			printf("Response");
      }
      printf("\n");
    }
}
