#include "sctp.h"
#include <netinet/ip_icmp.h>


void icmp_analyze(struct icmp * , const u_char *, int, u_char  );

void tcp_analyze(struct tcphdr * ,const u_char *, int  , int , u_char);

void sctp_analyze(struct sctphdr * ,const u_char *, int , u_char);

void udp_analyze(struct udphdr * ,const u_char *, int , u_char);
