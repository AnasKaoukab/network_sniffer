#include <netinet/if_ether.h>

void packet_hdlr(u_char *, const struct pcap_pkthdr *,const u_char *);
void ethernet_analyze(struct ether_header *,const u_char *,const struct pcap_pkthdr *,u_char );
