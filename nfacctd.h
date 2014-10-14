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

/*  NetFlow Export Version 9 Header Format  */
struct struct_header_v9 {
  u_int16_t version;		/* version = 9 */
  u_int16_t count;		/* The number of records in PDU. */
  u_int32_t sysUptime;		/* Current time in msecs since router booted */
  u_int32_t unix_secs;		/* Current seconds since 0000 UTC 1970 */
  u_int32_t flow_sequence;	/* Sequence number of total flows seen */
  u_int32_t source_id;		/* Source id */
};

/* NetFlow Export version 1 */
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

/* NetFlow Export version 5 */
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

/* NetFlow Export version 9 */
struct template_field_v9 {
  u_int16_t type;
  u_int16_t len;
}; 

struct template_hdr_v9 {
  u_int16_t flow_id; /* 0 */
  u_int16_t flow_len;
  u_int16_t template_id;
  u_int16_t num;
};

struct data_hdr_v9 {
  u_int16_t flow_id; /* >= 256 */
  u_int16_t flow_len;
};

/* defines */
#define DEFAULT_NFACCTD_PORT 2100
#define NETFLOW_MSG_SIZE 1550
#define V1_MAXFLOWS 24  /* max records in V1 packet */
#define V5_MAXFLOWS 30  /* max records in V5 packet */
#define TEMPLATE_CACHE_ENTRIES 255

#define NF_TIME_MSECS 0 /* times are in msecs */
#define NF_TIME_SECS 1 /* times are in secs */ 
#define NF_TIME_NEW 2 /* ignore netflow engine times and generate new ones */ 

#define NF_AS_KEEP 0 /* Keep AS numbers in NetFlow packets */
#define NF_AS_NEW 1 /* ignore AS numbers in NetFlow packets and generate new ones */ 

/* NetFlow V9 stuff */
#define NF9_TEMPLATE_FLOWSET_ID         0
#define NF9_OPTIONS_FLOWSET_ID          1
#define NF9_MIN_RECORD_FLOWSET_ID       256
#define NF9_MAX_DEFINED_FIELD		100

/* Flowset record types the we care about */
#define NF9_IN_BYTES			1
#define NF9_IN_PACKETS			2
#define NF9_FLOWS			3
#define NF9_L4_PROTOCOL			4
#define NF9_SRC_TOS                     5
#define NF9_TCP_FLAGS                   6
#define NF9_L4_SRC_PORT                 7
#define NF9_IPV4_SRC_ADDR               8
#define NF9_SRC_MASK                    9
#define NF9_INPUT_SNMP                  10
#define NF9_L4_DST_PORT                 11
#define NF9_IPV4_DST_ADDR               12
#define NF9_DST_MASK                    13
#define NF9_OUTPUT_SNMP                 14
#define NF9_IPV4_NEXT_HOP               15
#define NF9_SRC_AS                      16
#define NF9_DST_AS                      17
#define NF9_BGP_IPV4_NEXT_HOP		18
#define NF9_MUL_DST_PKTS                19
#define NF9_MUL_DST_BYTES               20
/* ... */
#define NF9_LAST_SWITCHED               21
#define NF9_FIRST_SWITCHED              22
/* ... */
#define NF9_IPV6_SRC_ADDR               27
#define NF9_IPV6_DST_ADDR               28
#define NF9_IPV6_SRC_MASK               29
#define NF9_IPV6_DST_MASK               30
#define NF9_ICMP_TYPE                   32
/* ... */
#define NF9_ENGINE_TYPE                 38
#define NF9_ENGINE_ID                   39
/* ... */
#define NF9_SRC_MAC                     56
#define NF9_DST_MAC                     57
#define NF9_SRC_VLAN                    58
#define NF9_DST_VLAN                    59
#define NF9_IP_PROTOCOL_VERSION         60
#define NF9_DIRECTION                   61
#define NF9_IPV6_NEXT_HOP		62
#define NF9_BGP_IPV6_NEXT_HOP		63

struct hosts_table {
  unsigned short int num;
  struct host_addr table[MAX_MAP_ENTRIES];
};

/* Ordered Template field */
struct otpl_field {
  u_int16_t off;
  u_int16_t len;
};

struct template_cache_entry {
  struct host_addr agent;		/* NetFlow Exporter agent */
  u_int32_t source_id;			/* Exporter Observation Domain */
  u_int16_t template_id;		/* template ID */
  u_int16_t num;			/* number of fields described into template */ 
  u_int16_t len;			/* total length of the described flowset */
  struct otpl_field tpl[NF9_MAX_DEFINED_FIELD];
  struct template_cache_entry *next;	
};

struct template_cache {
  u_int16_t num;
  struct template_cache_entry *c[TEMPLATE_CACHE_ENTRIES];
};

/* functions */
#if (!defined __NFACCTD_C)
#define EXT extern
#else
#define EXT
#endif
EXT void process_v1_packet(unsigned char *, u_int16_t, struct packet_ptrs *, struct plugin_requests *);
EXT void process_v5_packet(unsigned char *, u_int16_t, struct packet_ptrs *, struct plugin_requests *);
EXT void process_v9_packet(unsigned char *, u_int16_t, struct packet_ptrs *, struct packet_ptrs *, struct plugin_requests *);
EXT void load_allow_file(char *, struct hosts_table *);
EXT int check_allow(struct hosts_table *, struct sockaddr *);
EXT int NF_find_id(struct packet_ptrs *);

EXT struct template_cache tpl_cache;
#undef EXT

#if (!defined __NFV9_TEMPLATE_C)
#define EXT extern
#else
#define EXT
#endif
EXT void handle_template_v9(struct template_hdr_v9 *, struct packet_ptrs *);
EXT struct template_cache_entry *find_template_v9(u_int16_t, struct packet_ptrs *);
EXT struct template_cache_entry *insert_template_v9(struct template_hdr_v9 *, struct packet_ptrs *);
EXT void refresh_template_v9(struct template_hdr_v9 *, struct template_cache_entry *, struct packet_ptrs *);
#undef EXT

