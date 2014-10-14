sbin_PROGRAMS = pmacctd nfacctd
bin_PROGRAMS = pmacct @EXTRABIN@ 
EXTRA_PROGRAMS = pmmyplay pmpgplay
pmacctd_PLUGINS = @PLUGINS@
pmacctd_SOURCES = pmacctd.c signals.c util.c strlcpy.c plugin_hooks.c \
	server.c acct.c memory.c ll.c cfg.c imt_plugin.c log.c pkt_handlers.c \
	cfg_handlers.c net_aggr.c bpf_filter.c print_plugin.c ip_frag.c 
pmacctd_LDFLAGS = $(DEFS) 
pmacctd_LDADD = $(pmacctd_PLUGINS)
nfacctd_SOURCES = nfacctd.c signals.c util.c strlcpy.c plugin_hooks.c \
        server.c acct.c memory.c ll.c cfg.c imt_plugin.c log.c pkt_handlers.c \
        cfg_handlers.c net_aggr.c bpf_filter.c print_plugin.c nf_map.c \
	nf_map_handlers.c
nfacctd_LDFLAGS = $(DEFS)
nfacctd_LDADD = $(pmacctd_PLUGINS)
pmacct_SOURCES = pmacct.c strlcpy.c 
pmmyplay_SOURCES = pmmyplay.c strlcpy.c sql_handlers.c
pmpgplay_SOURCES = pmpgplay.c strlcpy.c sql_handlers.c
