/* Netflow stuff */

/*  NetFlow Export Version 1 Header Format  */
struct struct_header_v1  {
  u_int16_t version;		/* Current version = 1 */
  u_int16_t count;		/* The number of records in PDU. */
  u_int32_t SysUptime;		/* Current time in msecs since router booted */
  u_int32_t unix_secs;		/* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;		/* Residual nanoseconds since 0000 UTC 1970 */
};

/*  NetFlow Export Version 5 Header Format  */
struct struct_header_v5 {
  u_int16_t version;		/* Version = 5 */
  u_int16_t count;		/* The number of records in PDU. */
  u_int32_t SysUptime;		/* Current time in msecs since router booted */
  u_int32_t unix_secs;		/* Current seconds since 0000 UTC 1970 */
  u_int32_t unix_nsecs;		/* Residual nanoseconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;	/* Sequence number of total flows seen */
  unsigned char engine_type;    /* Type of flow switching engine (RP,VIP,etc.) */
  unsigned char engine_id;      /* Slot number of the flow switching engine */
};

/* NetFlow Export version 1  */
struct struct_export_v1 {
  struct in_addr srcaddr;	/* Source IP Address */
  struct in_addr dstaddr;	/* Destination IP Address */
  struct in_addr nexthop;	/* Next hop router's IP Address */
  u_int16_t input;		/* Input interface index */
  u_int16_t output;    		/* Output interface index */
  u_int32_t dPkts;      	/* Packets sent in Duration (milliseconds between 1st & last packet in this flow)*/
  u_int32_t dOctets;    	/* Octets sent in Duration (milliseconds between 1st & last packet in this flow)*/
  u_int32_t First;      	/* SysUptime at start of flow */
  u_int32_t Last;       	/* and of last packet of the flow */
  u_int16_t srcport;   		/* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport;   		/* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t pad;       		/* pad to word boundary */
  unsigned char prot;           /* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  unsigned char tos;            /* IP Type-of-Service */
  unsigned char pad_2[8];	/* pad to word boundary */
};

/* NetFlow Export version 5  */
struct struct_export_v5 {
  struct in_addr srcaddr;       /* Source IP Address */
  struct in_addr dstaddr;       /* Destination IP Address */
  struct in_addr nexthop;       /* Next hop router's IP Address */
  u_int16_t input;   		/* Input interface index */
  u_int16_t output;  		/* Output interface index */
  u_int32_t dPkts;    		/* Packets sent in Duration (milliseconds between 1st & last packet in this flow) */
  u_int32_t dOctets;  		/* Octets sent in Duration (milliseconds between 1st & last packet in this flow) */
  u_int32_t First;    		/* SysUptime at start of flow */
  u_int32_t Last;     		/* and of last packet of the flow */
  u_int16_t srcport; 		/* TCP/UDP source port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  u_int16_t dstport; 		/* TCP/UDP destination port number (.e.g, FTP, Telnet, etc.,or equivalent) */
  unsigned char pad;          	/* pad to word boundary */
  unsigned char tcp_flags;    	/* Cumulative OR of tcp flags */
  unsigned char prot;         	/* IP protocol, e.g., 6=TCP, 17=UDP, etc... */
  unsigned char tos;          	/* IP Type-of-Service */
  u_int16_t dst_as;  		/* dst peer/origin Autonomous System */
  u_int16_t src_as;  		/* source peer/origin Autonomous System */
  unsigned char dst_mask;       /* destination route's mask bits */
  unsigned char src_mask;       /* source route's mask bits */
  u_int16_t pad_1;   		/* pad to word boundary */
};

/* defines */
#define DEFAULT_NFACCTD_PORT 2100
#define NETFLOW_MSG_SIZE 1550
#define V1_MAXFLOWS 24  /* max records in V1 packet */
#define V5_MAXFLOWS 30  /* max records in V5 packet */
#define MAX_MAP_ENTRIES 128 
#define N_MAP_HANDLERS 3 

#define NF_TIME_MSECS 0 /* times are in msecs */
#define NF_TIME_SECS 1 /* times are in secs */ 
#define NF_TIME_NEW 2 /* ignore netflow engine times and generate new ones */ 

typedef int (*nf_pktmap_handler) (struct packet_ptrs *, void *, void *);

struct hosts_table {
  unsigned short int num;
  struct in_addr table[MAX_MAP_ENTRIES];
};

struct id_entry {
  u_int16_t id;
  struct in_addr agent_ip;
  u_int16_t input; /* input interface index */ 
  u_int16_t output; /* output interface index */ 
  nf_pktmap_handler func[N_MAP_HANDLERS]; 
};

struct id_table {
  unsigned short int num;
  struct id_entry e[MAX_MAP_ENTRIES];
};

struct _map_dictionary_line {
  char key[SRVBUFLEN];
  int (*func)(struct id_entry *, char *);
};

/* functions */
void process_v1_packet(unsigned char *, struct packet_ptrs *);
void process_v5_packet(unsigned char *, struct packet_ptrs *);
void load_allow_file(char *, struct hosts_table *);
void load_id_file(char *, struct id_table *);
int find_id(struct packet_ptrs *);
