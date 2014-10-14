/* prototypes */
#if (!defined __ADDR_C)
#define EXT extern
#else
#define EXT
#endif
EXT unsigned int str_to_addr(const char *, struct host_addr *);
EXT unsigned int addr_to_str(char *, const struct host_addr *);
EXT unsigned int addr_to_sa(struct sockaddr *, struct host_addr *, u_int16_t);
EXT unsigned int sa_to_addr(struct sockaddr *, struct host_addr *, u_int16_t *);
EXT unsigned int sa_addr_cmp(struct sockaddr *, struct host_addr *);
EXT void *pm_htonl6(void *);
EXT void *pm_ntohl6(void *);
EXT unsigned int ip6_addr_cmp(void *, void *);
EXT void ip6_addr_cpy(void *, void *);
EXT void etheraddr_string(const u_char *, char *);
EXT int string_etheraddr(const u_char *, char *);

#undef EXT
