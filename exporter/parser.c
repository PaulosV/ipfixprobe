/**
 * \file parser.c
 * \date 2019
 * \author Jiri Havranek <havranek@cesnet.cz>
 */
/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.

 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
*/

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "types.h"
#include "parser.h"

enum fpp_return_code fpp_parse_packet(struct fpp_parser_s *parser, const uint8_t * packet_ptr, uint32_t packet_len, struct packet_hdr_s ** out)
{ 
   enum fpp_return_code fpp_error_code = ParserDefaultReject;
   const uint8_t * fpp_packet_start = packet_ptr;
   const uint8_t * fpp_packet_end = packet_ptr + packet_len;
   uint32_t fpp_packet_offset_bits = 0;
   struct packet_hdr_s * hdr = NULL;
   struct packet_hdr_s * last_hdr = NULL;
   struct etherip_h etherip_0;
   struct ieee802_1q_h vlan_q_0;
   struct ieee802_1q_h vlan_ad_0;
   struct ieee802_1ah_h vlan_ah_0;
   struct mpls_h mpls_0;
   struct eompls_h eompls_0;
   struct trill_h trill_0;
   struct pppoe_h pppoe_0;
   struct gre_h gre_0;
   struct gre_sre_h gre_sre_0;
   struct l2tp_h l2tp_0;
   struct vxlan_h vxlan_0;
   struct genv_h genv_0;
   struct gtp_v0_h gtp_v0_0;
   struct gtp_v1_h gtp_v1_0;
   struct gtp_v2_h gtp_v2_0;
   struct gtp_v1_next_hdr_h gtp_v1_next_hdr_0;
   struct teredo_auth_h teredo_auth_0;
   struct teredo_origin_h teredo_origin_0;
   struct pptp_uncomp_proto_h pptp_uncomp_proto_0;
   struct pptp_comp_proto_h pptp_comp_proto_0;
   struct ipv6_hop_opt_h ipv6_hop_opt_0;
   struct ipv6_dst_opt_h ipv6_dst_opt_0;
   struct ipv6_routing_h ipv6_routing_0;
   struct ipv6_fragment_h ipv6_fragment_0;
   struct ipv6_ah_h ipv6_ah_0;
   uint16_t udp_src_port_0;
   uint8_t tmp;
   uint16_t tmp_0;
   uint8_t tmp_1;
   uint8_t tmp_3;
   uint16_t tmp_5;
   uint8_t tmp_9;
   uint8_t tmp_10;
   uint8_t tmp_14;
   uint8_t tmp_15;
   uint16_t tmp_16;
   uint8_t tmp_17;
   uint8_t tmp_18;
   struct headers_s headers;


   (void) fpp_error_code;
   (void) fpp_packet_start;
   (void) fpp_packet_end;
   (void) fpp_packet_offset_bits;
   (void) hdr;
   (void) last_hdr;
   (void) etherip_0;
   (void) vlan_q_0;
   (void) vlan_ad_0;
   (void) vlan_ah_0;
   (void) mpls_0;
   (void) eompls_0;
   (void) trill_0;
   (void) pppoe_0;
   (void) gre_0;
   (void) gre_sre_0;
   (void) l2tp_0;
   (void) vxlan_0;
   (void) genv_0;
   (void) gtp_v0_0;
   (void) gtp_v1_0;
   (void) gtp_v2_0;
   (void) gtp_v1_next_hdr_0;
   (void) teredo_auth_0;
   (void) teredo_origin_0;
   (void) pptp_uncomp_proto_0;
   (void) pptp_comp_proto_0;
   (void) ipv6_hop_opt_0;
   (void) ipv6_dst_opt_0;
   (void) ipv6_routing_0;
   (void) ipv6_fragment_0;
   (void) ipv6_ah_0;
   (void) udp_src_port_0;
   (void) tmp;
   (void) tmp_0;
   (void) tmp_1;
   (void) tmp_3;
   (void) tmp_5;
   (void) tmp_9;
   (void) tmp_10;
   (void) tmp_14;
   (void) tmp_15;
   (void) tmp_16;
   (void) tmp_17;
   (void) tmp_18;

   headers.eth = NULL;
   headers.ipv4 = NULL;
   headers.ipv6 = NULL;
   headers.tcp = NULL;
   headers.udp = NULL;
   headers.icmp = NULL;
   headers.icmp6 = NULL;
   headers.payload = NULL;

   *out = NULL;
   goto start;
start:
   { 
      goto parse_ethernet;
   }
parse_ethernet:
   { 
      if (fpp_packet_start + BYTES(fpp_packet_offset_bits + 112) > fpp_packet_end) { fpp_error_code = PacketTooShort; goto exit; }
      if (parser->link_count >= PARSER_MAX_LINK_COUNT || parser->hdr_counts[ethernet_h] >= PARSER_MAX_HEADER_COUNT) { fpp_error_code = OutOfMemory; goto exit; }
      headers.eth = &parser->eth[parser->hdr_counts[ethernet_h]++];
      hdr = &parser->links[parser->link_count++];
      hdr->type = ethernet_h;
      hdr->data = headers.eth;
      hdr->header_offset = fpp_packet_offset_bits / 8;
      hdr->next = NULL;
      if (last_hdr != NULL) { last_hdr->next = hdr; last_hdr = hdr; } else { *out = hdr; last_hdr = hdr; }
      headers.eth[0].dst_addr = (uint64_t)(ntohll(load_dword(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 16) & FPP_MASK(uint64_t, 48);
      fpp_packet_offset_bits += 48;
      headers.eth[0].src_addr = (uint64_t)(ntohll(load_dword(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 16) & FPP_MASK(uint64_t, 48);
      fpp_packet_offset_bits += 48;
      headers.eth[0].ethertype = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;

      switch (headers.eth[0].ethertype) { 
         case 2048: goto parse_ipv4;
         case 34525: goto parse_ipv6;
         case 34887: goto parse_mpls;
         case 34888: goto parse_mpls;
         case 33024: goto parse_vlan_q;
         case 34984: goto parse_vlan_ad;
         case 35047: goto parse_vlan_ah;
         case 8947: goto parse_trill;
         case 34916: goto parse_pppoe;
         case 34915: goto reject;
         default: goto reject;
      }
      goto exit;
   }
parse_vlan_q:
   { 
      vlan_q_0.pcp = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 5) & FPP_MASK(uint8_t, 3);
      fpp_packet_offset_bits += 3;
      vlan_q_0.cfi = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 4) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      vlan_q_0.vid = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint16_t, 12));
      fpp_packet_offset_bits += 12;
      vlan_q_0.ethertype = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;

      switch (vlan_q_0.ethertype) { 
         case 2048: goto parse_ipv4;
         case 34525: goto parse_ipv6;
         case 34887: goto parse_mpls;
         case 34888: goto parse_mpls;
         case 33024: goto parse_vlan_q;
         case 34984: goto parse_vlan_ad;
         case 8947: goto parse_trill;
         case 34916: goto parse_pppoe;
         case 34915: goto reject;
         default: goto reject;
      }
      goto exit;
   }
parse_vlan_ad:
   { 
      vlan_ad_0.pcp = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 5) & FPP_MASK(uint8_t, 3);
      fpp_packet_offset_bits += 3;
      vlan_ad_0.cfi = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 4) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      vlan_ad_0.vid = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint16_t, 12));
      fpp_packet_offset_bits += 12;
      vlan_ad_0.ethertype = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;

      switch (vlan_ad_0.ethertype) { 
         case 2048: goto parse_ipv4;
         case 34525: goto parse_ipv6;
         case 34887: goto parse_mpls;
         case 34888: goto parse_mpls;
         case 33024: goto parse_vlan_q;
         case 35047: goto parse_vlan_ah;
         case 8947: goto parse_trill;
         case 34916: goto parse_pppoe;
         case 34915: goto reject;
         default: goto reject;
      }
      goto exit;
   }
parse_vlan_ah:
   { 
      vlan_ah_0.prio = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 5) & FPP_MASK(uint8_t, 3);
      fpp_packet_offset_bits += 3;
      vlan_ah_0.drop = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 4) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      vlan_ah_0.nca = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 3) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      vlan_ah_0.res1 = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 2) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      vlan_ah_0.res2 = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint8_t, 2));
      fpp_packet_offset_bits += 2;
      vlan_ah_0.isid = (uint32_t)(ntohl(load_word(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 8) & FPP_MASK(uint32_t, 24);
      fpp_packet_offset_bits += 24;

      goto parse_ethernet;
   }
parse_trill:
   { 
      trill_0.version = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 6) & FPP_MASK(uint8_t, 2);
      fpp_packet_offset_bits += 2;
      trill_0.res = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 4) & FPP_MASK(uint8_t, 2);
      fpp_packet_offset_bits += 2;
      trill_0.m = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 3) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      trill_0.op_len = (uint8_t)(ntohs(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 6) & FPP_MASK(uint8_t, 5);
      fpp_packet_offset_bits += 5;
      trill_0.hop_cnt = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint8_t, 6));
      fpp_packet_offset_bits += 6;
      trill_0.egress_nick = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      trill_0.ingress_nick = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      fpp_packet_offset_bits += ((uint32_t)(trill_0.op_len)) << (5);

      goto parse_ethernet;
   }
parse_mpls:
   { 
      mpls_0.label = (uint32_t)(ntohl(load_word(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 12) & FPP_MASK(uint32_t, 20);
      fpp_packet_offset_bits += 20;
      mpls_0.tc = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 1) & FPP_MASK(uint8_t, 3);
      fpp_packet_offset_bits += 3;
      mpls_0.bos = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint8_t, 1));
      fpp_packet_offset_bits += 1;
      mpls_0.ttl = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;

      switch (mpls_0.bos) { 
         case 0: goto parse_mpls;
         case 1: goto parse_mpls_end;
         default: goto reject;
      }
      goto exit;
   }
parse_mpls_end:
   { 
      tmp = (((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits)) >> 4) & FPP_MASK(uint8_t, 4)));;

      switch (tmp) { 
         case 4: goto parse_ipv4;
         case 6: goto parse_ipv6;
         case 0: goto parse_eompls;
         default: goto reject;
      }
      goto exit;
   }
parse_eompls:
   { 
      eompls_0.zero = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 4) & FPP_MASK(uint8_t, 4);
      fpp_packet_offset_bits += 4;
      eompls_0.res = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint16_t, 12));
      fpp_packet_offset_bits += 12;
      eompls_0.seq_num = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;

      goto parse_ethernet;
   }
parse_pppoe:
   { 
      pppoe_0.version = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 4) & FPP_MASK(uint8_t, 4);
      fpp_packet_offset_bits += 4;
      pppoe_0.type = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint8_t, 4));
      fpp_packet_offset_bits += 4;
      pppoe_0.code = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      pppoe_0.sid = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      pppoe_0.len = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;

      switch (pppoe_0.code) { 
         case 0: goto parse_pptp;
         default: goto reject;
      }
      goto exit;
   }
parse_pptp:
   { 
      tmp_0 = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));;

      switch (tmp_0) { 
         case 65283: goto parse_pptp_uncomp_addr_cntrl;
         default: goto parse_pptp_comp_addr_cntrl;
      }
      goto exit;
   }
parse_pptp_uncomp_addr_cntrl:
   { 
      fpp_packet_offset_bits += 16;
      tmp_1 = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));;

      switch ((tmp_1) & (1)) { 
         case 0: goto parse_pptp_uncomp_proto;
         case 1: goto parse_pptp_comp_proto;
         default: goto reject;
      }
      goto exit;
   }
parse_pptp_comp_addr_cntrl:
   { 
      tmp_3 = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));;

      switch ((tmp_3) & (1)) { 
         case 0: goto parse_pptp_uncomp_proto;
         case 1: goto parse_pptp_comp_proto;
         default: goto reject;
      }
      goto exit;
   }
parse_pptp_uncomp_proto:
   { 
      pptp_uncomp_proto_0.proto = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;

      switch (pptp_uncomp_proto_0.proto) { 
         case 33: goto parse_ipv4;
         case 87: goto parse_ipv6;
         case 253: goto accept;
         case 49185: goto accept;
         default: goto reject;
      }
      goto exit;
   }
parse_pptp_comp_proto:
   { 
      pptp_comp_proto_0.proto = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;

      switch ((uint16_t)(pptp_comp_proto_0.proto)) { 
         case 33: goto parse_ipv4;
         case 87: goto parse_ipv6;
         case 253: goto accept;
         case 49185: goto accept;
         default: goto reject;
      }
      goto exit;
   }
parse_ipv4:
   { 
      if (fpp_packet_start + BYTES(fpp_packet_offset_bits + 160) > fpp_packet_end) { fpp_error_code = PacketTooShort; goto exit; }
      if (parser->link_count >= PARSER_MAX_LINK_COUNT || parser->hdr_counts[ipv4_h] >= PARSER_MAX_HEADER_COUNT) { fpp_error_code = OutOfMemory; goto exit; }
      headers.ipv4 = &parser->ipv4[parser->hdr_counts[ipv4_h]++];
      hdr = &parser->links[parser->link_count++];
      hdr->type = ipv4_h;
      hdr->data = headers.ipv4;
      hdr->header_offset = fpp_packet_offset_bits / 8;
      hdr->next = NULL;
      if (last_hdr != NULL) { last_hdr->next = hdr; last_hdr = hdr; } else { *out = hdr; last_hdr = hdr; }
      headers.ipv4[0].version = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 4) & FPP_MASK(uint8_t, 4);
      fpp_packet_offset_bits += 4;
      headers.ipv4[0].ihl = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint8_t, 4));
      fpp_packet_offset_bits += 4;
      headers.ipv4[0].diffserv = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      headers.ipv4[0].total_len = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      headers.ipv4[0].identification = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      headers.ipv4[0].flags = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 5) & FPP_MASK(uint8_t, 3);
      fpp_packet_offset_bits += 3;
      headers.ipv4[0].frag_offset = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint16_t, 13));
      fpp_packet_offset_bits += 13;
      headers.ipv4[0].ttl = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      headers.ipv4[0].protocol = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      headers.ipv4[0].hdr_checksum = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      headers.ipv4[0].src_addr = ntohl((uint32_t)(load_word(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 32;
      headers.ipv4[0].dst_addr = ntohl((uint32_t)(load_word(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 32;
      fpp_packet_offset_bits += (uint32_t)((((int32_t)((uint32_t)(headers.ipv4[0].ihl))) + (-5)) << (5));

      switch (headers.ipv4[0].protocol) { 
         case 6: goto parse_tcp;
         case 17: goto parse_udp;
         case 1: goto parse_icmp;
         case 47: goto parse_gre;
         case 4: goto parse_ipv4;
         case 41: goto parse_ipv6;
         case 97: goto parse_etherip;
         case 137: goto parse_mpls;
         default: goto accept;
      }
      goto exit;
   }
parse_ipv6:
   { 
      if (fpp_packet_start + BYTES(fpp_packet_offset_bits + 320) > fpp_packet_end) { fpp_error_code = PacketTooShort; goto exit; }
      if (parser->link_count >= PARSER_MAX_LINK_COUNT || parser->hdr_counts[ipv6_h] >= PARSER_MAX_HEADER_COUNT) { fpp_error_code = OutOfMemory; goto exit; }
      headers.ipv6 = &parser->ipv6[parser->hdr_counts[ipv6_h]++];
      hdr = &parser->links[parser->link_count++];
      hdr->type = ipv6_h;
      hdr->data = headers.ipv6;
      hdr->header_offset = fpp_packet_offset_bits / 8;
      hdr->next = NULL;
      if (last_hdr != NULL) { last_hdr->next = hdr; last_hdr = hdr; } else { *out = hdr; last_hdr = hdr; }
      headers.ipv6[0].version = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 4) & FPP_MASK(uint8_t, 4);
      fpp_packet_offset_bits += 4;
      headers.ipv6[0].traffic_class = (uint8_t)(ntohs(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 4) & FPP_MASK(uint8_t, 8);
      fpp_packet_offset_bits += 8;
      headers.ipv6[0].flow_label = (uint32_t)(ntohl(load_word(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 8) & FPP_MASK(uint32_t, 20);
      fpp_packet_offset_bits += 20;
      headers.ipv6[0].payload_len = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      headers.ipv6[0].next_hdr = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      headers.ipv6[0].hop_limit = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      headers.ipv6[0].src_addr[0] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 0)) >> 0);
      headers.ipv6[0].src_addr[1] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 8)) >> 0);
      headers.ipv6[0].src_addr[2] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 16)) >> 0);
      headers.ipv6[0].src_addr[3] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 24)) >> 0);
      headers.ipv6[0].src_addr[4] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 32)) >> 0);
      headers.ipv6[0].src_addr[5] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 40)) >> 0);
      headers.ipv6[0].src_addr[6] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 48)) >> 0);
      headers.ipv6[0].src_addr[7] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 56)) >> 0);
      headers.ipv6[0].src_addr[8] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 64)) >> 0);
      headers.ipv6[0].src_addr[9] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 72)) >> 0);
      headers.ipv6[0].src_addr[10] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 80)) >> 0);
      headers.ipv6[0].src_addr[11] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 88)) >> 0);
      headers.ipv6[0].src_addr[12] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 96)) >> 0);
      headers.ipv6[0].src_addr[13] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 104)) >> 0);
      headers.ipv6[0].src_addr[14] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 112)) >> 0);
      headers.ipv6[0].src_addr[15] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 120)) >> 0);
      fpp_packet_offset_bits += 128;
      headers.ipv6[0].dst_addr[0] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 0)) >> 0);
      headers.ipv6[0].dst_addr[1] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 8)) >> 0);
      headers.ipv6[0].dst_addr[2] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 16)) >> 0);
      headers.ipv6[0].dst_addr[3] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 24)) >> 0);
      headers.ipv6[0].dst_addr[4] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 32)) >> 0);
      headers.ipv6[0].dst_addr[5] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 40)) >> 0);
      headers.ipv6[0].dst_addr[6] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 48)) >> 0);
      headers.ipv6[0].dst_addr[7] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 56)) >> 0);
      headers.ipv6[0].dst_addr[8] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 64)) >> 0);
      headers.ipv6[0].dst_addr[9] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 72)) >> 0);
      headers.ipv6[0].dst_addr[10] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 80)) >> 0);
      headers.ipv6[0].dst_addr[11] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 88)) >> 0);
      headers.ipv6[0].dst_addr[12] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 96)) >> 0);
      headers.ipv6[0].dst_addr[13] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 104)) >> 0);
      headers.ipv6[0].dst_addr[14] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 112)) >> 0);
      headers.ipv6[0].dst_addr[15] = (uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits + 120)) >> 0);
      fpp_packet_offset_bits += 128;

      switch (headers.ipv6[0].next_hdr) { 
         case 6: goto parse_tcp;
         case 17: goto parse_udp;
         case 58: goto parse_icmp6;
         case 4: goto parse_ipv4;
         case 41: goto parse_ipv6;
         case 47: goto parse_gre;
         case 97: goto parse_etherip;
         case 137: goto parse_mpls;
         case 0: goto parse_ipv6_hop_opt;
         case 60: goto parse_ipv6_dst_opt;
         case 43: goto parse_ipv6_routing;
         case 44: goto parse_ipv6_fragment;
         case 51: goto parse_ipv6_ah;
         case 59: goto accept;
         default: goto accept;
      }
      goto exit;
   }
parse_ipv6_hop_opt:
   { 
      ipv6_hop_opt_0.next_hdr = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      ipv6_hop_opt_0.hdr_len = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      fpp_packet_offset_bits += (((uint32_t)(ipv6_hop_opt_0.hdr_len)) << (6)) + (48);
      headers.ipv6[0].next_hdr = ipv6_hop_opt_0.next_hdr;

      switch (ipv6_hop_opt_0.next_hdr) { 
         case 6: goto parse_tcp;
         case 17: goto parse_udp;
         case 58: goto parse_icmp6;
         case 4: goto parse_ipv4;
         case 41: goto parse_ipv6;
         case 47: goto parse_gre;
         case 97: goto parse_etherip;
         case 137: goto parse_mpls;
         case 0: goto parse_ipv6_hop_opt;
         case 60: goto parse_ipv6_dst_opt;
         case 43: goto parse_ipv6_routing;
         case 44: goto parse_ipv6_fragment;
         case 51: goto parse_ipv6_ah;
         case 59: goto accept;
         default: goto reject;
      }
      goto exit;
   }
parse_ipv6_dst_opt:
   { 
      ipv6_dst_opt_0.next_hdr = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      ipv6_dst_opt_0.hdr_len = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      fpp_packet_offset_bits += (((uint32_t)(ipv6_dst_opt_0.hdr_len)) << (6)) + (48);
      headers.ipv6[0].next_hdr = ipv6_dst_opt_0.next_hdr;

      switch (ipv6_dst_opt_0.next_hdr) { 
         case 6: goto parse_tcp;
         case 17: goto parse_udp;
         case 58: goto parse_icmp6;
         case 4: goto parse_ipv4;
         case 41: goto parse_ipv6;
         case 47: goto parse_gre;
         case 97: goto parse_etherip;
         case 137: goto parse_mpls;
         case 0: goto parse_ipv6_hop_opt;
         case 60: goto parse_ipv6_dst_opt;
         case 43: goto parse_ipv6_routing;
         case 44: goto parse_ipv6_fragment;
         case 51: goto parse_ipv6_ah;
         case 59: goto accept;
         default: goto reject;
      }
      goto exit;
   }
parse_ipv6_routing:
   { 
      ipv6_routing_0.next_hdr = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      ipv6_routing_0.hdr_len = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      fpp_packet_offset_bits += (((uint32_t)(ipv6_routing_0.hdr_len)) << (6)) + (48);
      headers.ipv6[0].next_hdr = ipv6_routing_0.next_hdr;

      switch (ipv6_routing_0.next_hdr) { 
         case 6: goto parse_tcp;
         case 17: goto parse_udp;
         case 58: goto parse_icmp6;
         case 4: goto parse_ipv4;
         case 41: goto parse_ipv6;
         case 47: goto parse_gre;
         case 97: goto parse_etherip;
         case 137: goto parse_mpls;
         case 0: goto parse_ipv6_hop_opt;
         case 60: goto parse_ipv6_dst_opt;
         case 43: goto parse_ipv6_routing;
         case 44: goto parse_ipv6_fragment;
         case 51: goto parse_ipv6_ah;
         case 59: goto accept;
         default: goto reject;
      }
      goto exit;
   }
parse_ipv6_fragment:
   { 
      ipv6_fragment_0.next_hdr = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      ipv6_fragment_0.res1 = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      ipv6_fragment_0.frag_offset = (uint16_t)(ntohs(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 3) & FPP_MASK(uint16_t, 13);
      fpp_packet_offset_bits += 13;
      ipv6_fragment_0.res2 = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 1) & FPP_MASK(uint8_t, 2);
      fpp_packet_offset_bits += 2;
      ipv6_fragment_0.m = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint8_t, 1));
      fpp_packet_offset_bits += 1;
      ipv6_fragment_0.id = ntohl((uint32_t)(load_word(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 32;
      headers.ipv6[0].next_hdr = ipv6_fragment_0.next_hdr;

      goto accept;
   }
parse_ipv6_ah:
   { 
      ipv6_ah_0.next_hdr = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      ipv6_ah_0.len = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      ipv6_ah_0.res = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      ipv6_ah_0.spi = ntohl((uint32_t)(load_word(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 32;
      fpp_packet_offset_bits += ((uint32_t)(ipv6_ah_0.len)) << (5);
      headers.ipv6[0].next_hdr = ipv6_ah_0.next_hdr;

      switch (ipv6_ah_0.next_hdr) { 
         case 6: goto parse_tcp;
         case 17: goto parse_udp;
         case 58: goto parse_icmp6;
         case 4: goto parse_ipv4;
         case 41: goto parse_ipv6;
         case 47: goto parse_gre;
         case 97: goto parse_etherip;
         case 137: goto parse_mpls;
         case 0: goto parse_ipv6_hop_opt;
         case 60: goto parse_ipv6_dst_opt;
         case 43: goto parse_ipv6_routing;
         case 44: goto parse_ipv6_fragment;
         case 51: goto parse_ipv6_ah;
         case 59: goto accept;
         default: goto reject;
      }
      goto exit;
   }
parse_etherip:
   { 
      etherip_0.version = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 4) & FPP_MASK(uint8_t, 4);
      fpp_packet_offset_bits += 4;
      etherip_0.reserved = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint16_t, 12));
      fpp_packet_offset_bits += 12;

      switch (etherip_0.version) { 
         case 3: goto parse_ethernet;
         default: goto reject;
      }
      goto exit;
   }
parse_gre:
   { 
      gre_0.C = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 7) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      gre_0.R = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 6) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      gre_0.K = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 5) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      gre_0.S = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 4) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      gre_0.s = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 3) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      gre_0.recur = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint8_t, 3));
      fpp_packet_offset_bits += 3;
      gre_0.A = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 7) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      gre_0.flags = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 3) & FPP_MASK(uint8_t, 4);
      fpp_packet_offset_bits += 4;
      gre_0.ver = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint8_t, 3));
      fpp_packet_offset_bits += 3;
      gre_0.proto = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;

      switch (gre_0.ver) { 
         case 0: goto parse_gre_v0;
         case 1: goto parse_gre_v1;
         default: goto reject;
      }
      goto exit;
   }
parse_gre_v0:
   { 
      fpp_packet_offset_bits += (((uint32_t)(gre_0.C)) | ((uint32_t)(gre_0.R))) << (5);
      fpp_packet_offset_bits += ((uint32_t)(gre_0.K)) << (5);
      fpp_packet_offset_bits += ((uint32_t)(gre_0.S)) << (5);

      switch (gre_0.R) { 
         case 1: goto parse_gre_sre;
         case 0: goto parse_gre_v0_fin;
         default: goto reject;
      }
      goto exit;
   }
parse_gre_v0_fin:
   { 
      switch (gre_0.proto) { 
         case 2048: goto parse_ipv4;
         case 34525: goto parse_ipv6;
         case 34827: goto parse_pptp;
         case 25944: goto parse_ethernet;
         case 34887: goto parse_mpls;
         case 34888: goto parse_mpls;
         default: goto reject;
      }
      goto exit;
   }
parse_gre_v1:
   { 
      fpp_packet_offset_bits += 32;
      fpp_packet_offset_bits += ((uint32_t)(gre_0.S)) << (5);
      fpp_packet_offset_bits += ((uint32_t)(gre_0.A)) << (5);

      switch (gre_0.proto) { 
         case 2048: goto parse_ipv4;
         case 34525: goto parse_ipv6;
         case 34827: goto parse_pptp;
         case 25944: goto parse_ethernet;
         case 34887: goto parse_mpls;
         case 34888: goto parse_mpls;
         default: goto reject;
      }
      goto exit;
   }
parse_gre_sre:
   { 
      gre_sre_0.addr_family = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      gre_sre_0.offset = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      gre_sre_0.length = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      fpp_packet_offset_bits += (uint32_t)(gre_sre_0.length);

      switch (gre_sre_0.length) { 
         case 0: goto parse_gre_v0_fin;
         default: goto parse_gre_sre;
      }
      goto exit;
   }
parse_l2tp:
   { 
      l2tp_0.type = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 7) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      l2tp_0.length = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 6) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      l2tp_0.res1 = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 4) & FPP_MASK(uint8_t, 2);
      fpp_packet_offset_bits += 2;
      l2tp_0.seq = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 3) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      l2tp_0.res2 = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 2) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      l2tp_0.offset = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 1) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      l2tp_0.priority = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint8_t, 1));
      fpp_packet_offset_bits += 1;
      l2tp_0.res3 = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 4) & FPP_MASK(uint8_t, 4);
      fpp_packet_offset_bits += 4;
      l2tp_0.version = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint8_t, 4));
      fpp_packet_offset_bits += 4;

      switch (l2tp_0.version) { 
         case 2: goto parse_l2tp_v2;
         default: goto reject;
      }
      goto exit;
   }
parse_l2tp_v2:
   { 
      fpp_packet_offset_bits += ((uint32_t)(l2tp_0.length)) << (4);
      fpp_packet_offset_bits += 32;
      fpp_packet_offset_bits += ((uint32_t)(l2tp_0.seq)) << (5);
      tmp_5 = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));;
      fpp_packet_offset_bits += (((uint32_t)(l2tp_0.offset)) * ((uint32_t)(tmp_5))) << (3);
      fpp_packet_offset_bits += ((uint32_t)(l2tp_0.offset)) << (4);

      switch (l2tp_0.type) { 
         case 0: goto parse_pptp;
         default: goto reject;
      }
      goto exit;
   }
parse_gtp:
   { 
      tmp_9 = (((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits)) >> 5) & FPP_MASK(uint8_t, 3)));;

      switch (tmp_9) { 
         case 0: goto parse_gtp_v0;
         case 1: goto parse_gtp_v1;
         case 2: goto parse_gtp_v2;
         default: goto reject;
      }
      goto exit;
   }
parse_gtp_v0:
   { 
      gtp_v0_0.version = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 5) & FPP_MASK(uint8_t, 3);
      fpp_packet_offset_bits += 3;
      gtp_v0_0.proto_type = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 4) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      gtp_v0_0.res1 = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 1) & FPP_MASK(uint8_t, 3);
      fpp_packet_offset_bits += 3;
      gtp_v0_0.snn = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint8_t, 1));
      fpp_packet_offset_bits += 1;
      gtp_v0_0.type = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      gtp_v0_0.length = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      gtp_v0_0.seq_num = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      gtp_v0_0.flow_label = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      gtp_v0_0.sndcp_num = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      gtp_v0_0.res2 = (uint32_t)(ntohl(load_word(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 8) & FPP_MASK(uint32_t, 24);
      fpp_packet_offset_bits += 24;
      gtp_v0_0.tid = ntohll((uint64_t)(load_dword(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 64;

      switch (gtp_v0_0.type) { 
         case 255: goto parse_gtp_fin;
         default: goto reject;
      }
      goto exit;
   }
parse_gtp_v1:
   { 
      gtp_v1_0.version = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 5) & FPP_MASK(uint8_t, 3);
      fpp_packet_offset_bits += 3;
      gtp_v1_0.proto_type = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 4) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      gtp_v1_0.res = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 3) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      gtp_v1_0.E = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 2) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      gtp_v1_0.S = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 1) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      gtp_v1_0.PN = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint8_t, 1));
      fpp_packet_offset_bits += 1;
      gtp_v1_0.type = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      gtp_v1_0.length = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      gtp_v1_0.TEID = ntohl((uint32_t)(load_word(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 32;

      switch ((((uint32_t)(gtp_v1_0.E)) | ((uint32_t)(gtp_v1_0.S))) | ((uint32_t)(gtp_v1_0.PN))) { 
         case 1: goto parse_gtp_v1_opt;
         case 0: goto parse_gtp_v1_check_type;
         default: goto reject;
      }
      goto exit;
   }
parse_gtp_v1_check_type:
   { 
      switch (gtp_v1_0.type) { 
         case 255: goto parse_gtp_fin;
         default: goto reject;
      }
      goto exit;
   }
parse_gtp_v1_opt:
   { 
      fpp_packet_offset_bits += 24;

      switch (gtp_v1_0.E) { 
         case 1: goto parse_gtp_v1_next_hdr;
         case 0: goto parse_gtp_v1_skip_nexthdr;
         default: goto reject;
      }
      goto exit;
   }
parse_gtp_v1_next_hdr:
   { 
      tmp_10 = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));;
      fpp_packet_offset_bits += (uint32_t)(((int32_t)(((uint32_t)(tmp_10)) << (5))) + (-8));
      gtp_v1_next_hdr_0.next_hdr = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;

      switch (gtp_v1_next_hdr_0.next_hdr) { 
         case 0: goto parse_gtp_v1_check_type;
         default: goto parse_gtp_v1_next_hdr;
      }
      goto exit;
   }
parse_gtp_v1_skip_nexthdr:
   { 
      fpp_packet_offset_bits += 8;

      switch (gtp_v1_0.type) { 
         case 255: goto parse_gtp_fin;
         default: goto reject;
      }
      goto exit;
   }
parse_gtp_v2:
   { 
      gtp_v2_0.version = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 5) & FPP_MASK(uint8_t, 3);
      fpp_packet_offset_bits += 3;
      gtp_v2_0.piggy_flag = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 4) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      gtp_v2_0.TEID_flag = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 3) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      gtp_v2_0.spare = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint8_t, 3));
      fpp_packet_offset_bits += 3;
      gtp_v2_0.type = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      gtp_v2_0.length = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      fpp_packet_offset_bits += ((uint32_t)(gtp_v2_0.TEID_flag)) << (5);
      fpp_packet_offset_bits += 32;

      switch (gtp_v2_0.type) { 
         case 255: goto parse_gtp_fin;
         default: goto reject;
      }
      goto exit;
   }
parse_gtp_fin:
   { 
      tmp_14 = (((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits)) >> 4) & FPP_MASK(uint8_t, 4)));;

      switch (tmp_14) { 
         case 4: goto parse_ipv4;
         case 6: goto parse_ipv6;
         default: goto reject;
      }
      goto exit;
   }
parse_teredo:
   { 
      tmp_15 = (((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits)) >> 4) & FPP_MASK(uint8_t, 4)));;

      switch (tmp_15) { 
         case 6: goto parse_ipv6;
         case 0: goto parse_teredo_hdr;
         default: goto reject;
      }
      goto exit;
   }
parse_teredo_hdr:
   { 
      tmp_16 = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));;

      switch (tmp_16) { 
         case 1: goto parse_teredo_auth_hdr;
         case 0: goto parse_teredo_origin_hdr;
         default: goto reject;
      }
      goto exit;
   }
parse_teredo_auth_hdr:
   { 
      teredo_auth_0.zero = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      teredo_auth_0.type = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      teredo_auth_0.id_len = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      teredo_auth_0.auth_len = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      fpp_packet_offset_bits += ((((uint32_t)(teredo_auth_0.id_len)) << (3)) + (((uint32_t)(teredo_auth_0.auth_len)) << (3))) + (72);
      tmp_17 = (((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits)) >> 4) & FPP_MASK(uint8_t, 4)));;

      switch (tmp_17) { 
         case 6: goto parse_ipv6;
         case 0: goto parse_teredo_hdr;
         default: goto reject;
      }
      goto exit;
   }
parse_teredo_origin_hdr:
   { 
      teredo_origin_0.zero = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      teredo_origin_0.type = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      teredo_origin_0.port = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      teredo_origin_0.ip = ntohl((uint32_t)(load_word(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 32;
      tmp_18 = (((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits)) >> 4) & FPP_MASK(uint8_t, 4)));;

      switch (tmp_18) { 
         case 6: goto parse_ipv6;
         case 0: goto parse_teredo_hdr;
         default: goto reject;
      }
      goto exit;
   }
parse_vxlan:
   { 
      vxlan_0.gbp_ext = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 7) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      vxlan_0.res1 = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 4) & FPP_MASK(uint8_t, 3);
      fpp_packet_offset_bits += 3;
      vxlan_0.vni_flag = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 3) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      vxlan_0.res2 = (uint8_t)(ntohs(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 7) & FPP_MASK(uint8_t, 4);
      fpp_packet_offset_bits += 4;
      vxlan_0.dont_learn = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 6) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      vxlan_0.res3 = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 4) & FPP_MASK(uint8_t, 2);
      fpp_packet_offset_bits += 2;
      vxlan_0.policy_applied = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 3) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      vxlan_0.res4 = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint8_t, 3));
      fpp_packet_offset_bits += 3;
      vxlan_0.gpolicy_id = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      vxlan_0.vni = (uint32_t)(ntohl(load_word(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 8) & FPP_MASK(uint32_t, 24);
      fpp_packet_offset_bits += 24;
      vxlan_0.res5 = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;

      goto parse_ethernet;
   }
parse_genv:
   { 
      genv_0.version = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 6) & FPP_MASK(uint8_t, 2);
      fpp_packet_offset_bits += 2;
      genv_0.opt_len = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint8_t, 6));
      fpp_packet_offset_bits += 6;
      genv_0.oam = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 7) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      genv_0.critical = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 6) & FPP_MASK(uint8_t, 1);
      fpp_packet_offset_bits += 1;
      genv_0.res1 = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint8_t, 6));
      fpp_packet_offset_bits += 6;
      genv_0.proto = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      genv_0.vni = (uint32_t)(ntohl(load_word(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 8) & FPP_MASK(uint32_t, 24);
      fpp_packet_offset_bits += 24;
      genv_0.res2 = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      fpp_packet_offset_bits += ((uint32_t)(genv_0.opt_len)) << (5);

      switch (genv_0.proto) { 
         case 25944: goto parse_ethernet;
         case 34888: goto parse_mpls;
         case 34887: goto parse_mpls;
         default: goto reject;
      }
      goto exit;
   }
parse_tcp:
   { 
      if (fpp_packet_start + BYTES(fpp_packet_offset_bits + 160) > fpp_packet_end) { fpp_error_code = PacketTooShort; goto exit; }
      if (parser->link_count >= PARSER_MAX_LINK_COUNT || parser->hdr_counts[tcp_h] >= PARSER_MAX_HEADER_COUNT) { fpp_error_code = OutOfMemory; goto exit; }
      headers.tcp = &parser->tcp[parser->hdr_counts[tcp_h]++];
      hdr = &parser->links[parser->link_count++];
      hdr->type = tcp_h;
      hdr->data = headers.tcp;
      hdr->header_offset = fpp_packet_offset_bits / 8;
      hdr->next = NULL;
      if (last_hdr != NULL) { last_hdr->next = hdr; last_hdr = hdr; } else { *out = hdr; last_hdr = hdr; }
      headers.tcp[0].src_port = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      headers.tcp[0].dst_port = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      headers.tcp[0].seq_num = ntohl((uint32_t)(load_word(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 32;
      headers.tcp[0].ack_num = ntohl((uint32_t)(load_word(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 32;
      headers.tcp[0].data_offset = (uint8_t)((load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) >> 4) & FPP_MASK(uint8_t, 4);
      fpp_packet_offset_bits += 4;
      headers.tcp[0].res = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))) & FPP_MASK(uint8_t, 4));
      fpp_packet_offset_bits += 4;
      headers.tcp[0].flags = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      headers.tcp[0].window = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      headers.tcp[0].checksum = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      headers.tcp[0].urgent_ptr = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      fpp_packet_offset_bits += (uint32_t)((((int32_t)((uint32_t)(headers.tcp[0].data_offset))) + (-5)) << (5));

      goto parse_payload;
   }
parse_udp:
   { 
      if (fpp_packet_start + BYTES(fpp_packet_offset_bits + 64) > fpp_packet_end) { fpp_error_code = PacketTooShort; goto exit; }
      if (parser->link_count >= PARSER_MAX_LINK_COUNT || parser->hdr_counts[udp_h] >= PARSER_MAX_HEADER_COUNT) { fpp_error_code = OutOfMemory; goto exit; }
      headers.udp = &parser->udp[parser->hdr_counts[udp_h]++];
      hdr = &parser->links[parser->link_count++];
      hdr->type = udp_h;
      hdr->data = headers.udp;
      hdr->header_offset = fpp_packet_offset_bits / 8;
      hdr->next = NULL;
      if (last_hdr != NULL) { last_hdr->next = hdr; last_hdr = hdr; } else { *out = hdr; last_hdr = hdr; }
      headers.udp[0].src_port = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      headers.udp[0].dst_port = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      headers.udp[0].len = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      headers.udp[0].checksum = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      udp_src_port_0 = headers.udp[0].src_port;

      switch (headers.udp[0].dst_port) { 
         case 1701: goto parse_l2tp;
         case 1723: goto parse_pptp;
         case 2123: goto parse_gtp;
         case 2152: goto parse_gtp;
         case 3386: goto parse_gtp;
         case 3544: goto parse_teredo;
         case 4789: goto parse_vxlan;
         case 6081: goto parse_genv;
         default: goto parse_udp_2;
      }
      goto exit;
   }
parse_udp_2:
   { 
      switch (udp_src_port_0) { 
         case 1701: goto parse_l2tp;
         case 1723: goto parse_pptp;
         case 2123: goto parse_gtp;
         case 2152: goto parse_gtp;
         case 3386: goto parse_gtp;
         case 3544: goto parse_teredo;
         case 4789: goto parse_vxlan;
         case 6081: goto parse_genv;
         default: goto parse_payload;
      }
      goto exit;
   }
parse_icmp:
   { 
      if (fpp_packet_start + BYTES(fpp_packet_offset_bits + 64) > fpp_packet_end) { fpp_error_code = PacketTooShort; goto exit; }
      if (parser->link_count >= PARSER_MAX_LINK_COUNT || parser->hdr_counts[icmp_h] >= PARSER_MAX_HEADER_COUNT) { fpp_error_code = OutOfMemory; goto exit; }
      headers.icmp = &parser->icmp[parser->hdr_counts[icmp_h]++];
      hdr = &parser->links[parser->link_count++];
      hdr->type = icmp_h;
      hdr->data = headers.icmp;
      hdr->header_offset = fpp_packet_offset_bits / 8;
      hdr->next = NULL;
      if (last_hdr != NULL) { last_hdr->next = hdr; last_hdr = hdr; } else { *out = hdr; last_hdr = hdr; }
      headers.icmp[0].type_ = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      headers.icmp[0].code = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      headers.icmp[0].hdr_checksum = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      headers.icmp[0].rest = ntohl((uint32_t)(load_word(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 32;

      goto accept;
   }
parse_icmp6:
   { 
      if (fpp_packet_start + BYTES(fpp_packet_offset_bits + 64) > fpp_packet_end) { fpp_error_code = PacketTooShort; goto exit; }
      if (parser->link_count >= PARSER_MAX_LINK_COUNT || parser->hdr_counts[icmpv6_h] >= PARSER_MAX_HEADER_COUNT) { fpp_error_code = OutOfMemory; goto exit; }
      headers.icmp6 = &parser->icmp6[parser->hdr_counts[icmpv6_h]++];
      hdr = &parser->links[parser->link_count++];
      hdr->type = icmpv6_h;
      hdr->data = headers.icmp6;
      hdr->header_offset = fpp_packet_offset_bits / 8;
      hdr->next = NULL;
      if (last_hdr != NULL) { last_hdr->next = hdr; last_hdr = hdr; } else { *out = hdr; last_hdr = hdr; }
      headers.icmp6[0].type_ = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      headers.icmp6[0].code = ((uint8_t)(load_byte(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 8;
      headers.icmp6[0].hdr_checksum = ntohs((uint16_t)(load_half(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 16;
      headers.icmp6[0].rest = ntohl((uint32_t)(load_word(fpp_packet_start, BYTES(fpp_packet_offset_bits))));
      fpp_packet_offset_bits += 32;

      goto accept;
   }
parse_payload:
   { 
      if (fpp_packet_start + BYTES(fpp_packet_offset_bits + 0) > fpp_packet_end) { fpp_error_code = PacketTooShort; goto exit; }
      if (parser->link_count >= PARSER_MAX_LINK_COUNT || parser->hdr_counts[payload_h] >= PARSER_MAX_HEADER_COUNT) { fpp_error_code = OutOfMemory; goto exit; }
      headers.payload = &parser->payload[parser->hdr_counts[payload_h]++];
      hdr = &parser->links[parser->link_count++];
      hdr->type = payload_h;
      hdr->data = headers.payload;
      hdr->header_offset = fpp_packet_offset_bits / 8;
      hdr->next = NULL;
      if (last_hdr != NULL) { last_hdr->next = hdr; last_hdr = hdr; } else { *out = hdr; last_hdr = hdr; }

      goto accept;
   }


accept:
   return NoError;
reject:
exit:
   return fpp_error_code;
}

void fpp_init(struct fpp_parser_s *parser)
{
   memset(parser, 0, sizeof(struct fpp_parser_s));
}
void fpp_free(struct fpp_parser_s *parser, struct packet_hdr_s *headers)
{
   while (headers != NULL) {
      parser->hdr_counts[headers->type]--;
      parser->link_count--;
      headers = headers->next;
   }
}
void fpp_clear(struct fpp_parser_s *parser)
{
   memset(parser, 0, sizeof(struct fpp_parser_s));
}