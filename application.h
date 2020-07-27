
struct dnshdr {
	u_int16_t query_id;
	u_int16_t flags;
	u_int16_t quest_count;
	u_int16_t answ_count;
	u_int16_t auth_count;
	u_int16_t add_count;
};

struct bootphdr {
	u_int8_t msg_type;
	u_int8_t hrdwr_type;
	u_int8_t hrdwr_addr_length;
	u_int8_t hops;
	u_int32_t trans_id;
	u_int16_t num_sec;
	u_int16_t flags;
	struct in_addr ciaddr;
	struct in_addr yiaddr;
	struct in_addr siaddr;
	struct in_addr giaddr;
	u_char hrdwr_caddr[16];
	u_char srv_name[64];
	u_char bpfile_name[128];
	u_int32_t magic_cookie;
};

void telnet_analyze( const u_char *, int ,int , u_char);
void imap_analyze( const u_char *, int ,int , u_char);
void smtp_analyze( const u_char *, int ,int , u_char);
void pop_analyze( const u_char *, int ,int , u_char);
void ftp_analyze( const u_char *, int ,int , u_char);
void http_analyze( const u_char *, int ,int , u_char);
void bootp_analyze(struct bootphdr * , const u_char *, int ,int , u_char);
void dns_analyze(struct dnshdr * ,const u_char *, int ,int , u_char);
