/*
    pmacct (Promiscuous mode IP Accounting package)
    pmacct is Copyright (C) 2003-2005 by Paolo Lucente
*/

/*
    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if no, write to the Free Software
    Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#if (defined __PKT_HANDLERS_C)
extern struct channels_list_entry channels_list[MAX_N_PLUGINS]; /* communication channels: core <-> plugins */
#endif

#if (!defined __PKT_HANDLERS_C)
#define EXT extern
#else
#define EXT
#endif
EXT pkt_handler phandler[N_PRIMITIVES];
#undef EXT

#if (!defined __PKT_HANDLERS_C)
#define EXT extern
#else
#define EXT
#endif
EXT void evaluate_packet_handlers(); 
EXT void src_mac_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void dst_mac_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void vlan_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void src_host_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void dst_host_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void src_port_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void dst_port_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void ip_tos_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void ip_proto_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void counters_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void id_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void flows_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);

EXT void NF_src_mac_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void NF_dst_mac_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void NF_vlan_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void NF_src_host_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void NF_dst_host_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void NF_src_port_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void NF_dst_port_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void NF_src_as_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void NF_dst_as_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void NF_ip_tos_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void NF_ip_proto_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void NF_counters_msecs_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void NF_counters_secs_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void NF_counters_new_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
EXT void NF_flows_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);

EXT void ptag_id_handler(struct channels_list_entry *, struct packet_ptrs *, struct pkt_data *);
#undef EXT

