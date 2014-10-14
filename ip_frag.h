/* defines */
#define IPFT_HASHSZ 256 
#define IPF_TIMEOUT 60 
#define PRUNE_INTERVAL 7200
#define PRUNE_OFFSET 1800 

/* structures */
struct ip_fragment {
  unsigned char tlhdr[8];	/* upper level info */ 
  u_int8_t got_first;		/* got first packet ? */
  u_int16_t a;			/* bytes accumulator */
  u_int32_t deadline;		/* timeout timestamp */
  u_int16_t ip_id;
  u_int8_t ip_p;
  u_int32_t ip_src;
  u_int32_t ip_dst;
  u_int16_t bucket;
  struct ip_fragment *lru_next;
  struct ip_fragment *lru_prev;
  struct ip_fragment *next;
  struct ip_fragment *prev;
};

struct lru_l {
  struct ip_fragment *root;
  struct ip_fragment *last;
};

/* global vars */
struct ip_fragment *ipft[IPFT_HASHSZ];
struct lru_l lru_list;

/* prototypes */
#if (!defined __IP_FRAG_C)
#define EXT extern
#else
#define EXT
#endif
EXT void init_ip_fragment_handler(); 
EXT int ip_fragment_handler(struct packet_ptrs *); 
EXT int find_fragment(struct packet_ptrs *); 
EXT int create_fragment(struct ip_fragment *, u_int8_t, unsigned int, struct packet_ptrs *); 
EXT unsigned int hash_fragment(u_int16_t, u_int32_t, u_int32_t, u_int8_t);
EXT void prune_old_fragments(u_int32_t); 
#undef EXT
