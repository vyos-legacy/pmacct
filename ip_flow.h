/* defines */
#define FLOW_TABLE_HASHSZ 256 
#define FLOW_GENERIC_LIFETIME 60 
#define FLOW_TCPFIN_LIFETIME 2 
#define FLOW_TCPRST_LIFETIME 0
#define FLOW_TABLE_PRUNE_INTERVAL 3600 
#define FLOW_TABLE_EMER_PRUNE_INTERVAL 60
#define DEFAULT_FLOW_BUFFER_SIZE 16384000 /* 16 Mb */

/* Flow closing flags */
#define FL_OPEN       0x00
#define FL_TCPFIN     0x01
#define FL_TCPRST     0x02

/* structures */
struct ip_flow_common {
  u_int16_t bucket;
  time_t closed;
  time_t last;
  u_int8_t ctype;
  u_int8_t proto;
};

struct ip_flow {
  struct ip_flow_common cmn;
  u_int32_t ip_src;
  u_int32_t ip_dst;
  u_int16_t port_src;
  u_int16_t port_dst;
  struct ip_flow *lru_next;
  struct ip_flow *lru_prev;
  struct ip_flow *next;
  struct ip_flow *prev;
};

struct flow_lru_l {
  struct ip_flow *root;
  struct ip_flow *last;
};

#if defined ENABLE_IPV6
struct ip_flow6 {
  struct ip_flow_common cmn;
  u_int32_t ip_src[4];
  u_int32_t ip_dst[4];
  u_int16_t port_src;
  u_int16_t port_dst;
  struct ip_flow6 *lru_next;
  struct ip_flow6 *lru_prev;
  struct ip_flow6 *next;
  struct ip_flow6 *prev;
};

struct flow_lru_l6 {
  struct ip_flow6 *root;
  struct ip_flow6 *last;
};
#endif

/* global vars */
struct ip_flow *ip_flow_table[FLOW_TABLE_HASHSZ];
struct flow_lru_l flow_lru_list;

#if defined ENABLE_IPV6
struct ip_flow6 *ip_flow_table6[FLOW_TABLE_HASHSZ];
struct flow_lru_l6 flow_lru_list6;
#endif

/* prototypes */
#if (!defined __IP_FLOW_C)
#define EXT extern
#else
#define EXT
#endif
EXT void init_ip_flow_handler(); /* wrapper */ 
EXT void init_ip4_flow_handler(); 
EXT int ip_flow_handler(struct packet_ptrs *); 
EXT int find_flow(u_int32_t, struct packet_ptrs *); 
EXT int create_flow(u_int32_t, struct ip_flow *, u_int8_t, unsigned int, struct packet_ptrs *); 
EXT inline unsigned int hash_flow(u_int32_t, u_int32_t, u_int16_t, u_int16_t, u_int8_t);
EXT void prune_old_flows(u_int32_t); 
EXT inline unsigned int is_expired(u_int32_t, struct ip_flow_common *);
EXT inline void is_closing(u_int32_t, struct packet_ptrs *, struct ip_flow_common *);

#if defined ENABLE_IPV6
EXT void init_ip6_flow_handler();
EXT int ip_flow6_handler(struct packet_ptrs *);
EXT unsigned int hash_flow6(u_int32_t, struct in6_addr *, struct in6_addr *);
EXT int find_flow6(u_int32_t, struct packet_ptrs *);
EXT int create_flow6(u_int32_t, struct ip_flow6 *, u_int8_t, unsigned int, struct packet_ptrs *);
EXT void prune_old_flows6(u_int32_t); 
#endif
#undef EXT
