/**
 * \file testovacipluginplugin.cpp
 * \brief Plugin for parsing testovaciplugin traffic.
 * \author Pavel Valach <valacpav@fit.cvut.cz>
 * \date 2021
 */
/*
 * Copyright (C) 2021 CESNET
 *
 * LICENSE TERMS
 *
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
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided as is'', and any express or implied
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
 *
 */

#include <iostream>

#include "testovacipluginplugin.h"
#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"
#include "ipfix-elements.h"

using namespace std;

#define TESTOVACIPLUGIN_UNIREC_TEMPLATE "WIREGUARD_SENDER,WIREGUARD_RECEIEVER" /* ToDO is this correct? */

UR_FIELDS (
   __uint128_t WIREGUARD_SENDER,
   __uint128_t WIREGUARD_RECEIVER
)

void TESTOVACIPLUGINPlugin::create_testovaci_record(Flow &rec, const Packet &pkt)
{
   if (ext_ptr == NULL) {
      ext_ptr = new RecordExtTESTOVACIPLUGIN();
   }

   if (update_testovaci_record(ext_ptr, pkt)) {
      rec.addExtension(ext_ptr);
      ext_ptr = NULL;
   }
}

bool TESTOVACIPLUGINPlugin::update_testovaci_record(RecordExtTESTOVACIPLUGIN *ext, const Packet &pkt)
{
   total++;
   if (pkt.src_port == 25) {
      return parse_smtp_response(pkt.payload, pkt.payload_length, ext);
   } else if (pkt.dst_port == 25) {
      return parse_smtp_command(pkt.payload, pkt.payload_length, ext);
   }

   return false;
}


TESTOVACIPLUGINPlugin::TESTOVACIPLUGINPlugin(const options_t &module_options)
{
   print_stats = module_options.print_stats;
}

TESTOVACIPLUGINPlugin::TESTOVACIPLUGINPlugin(const options_t &module_options, vector<plugin_opt> plugin_options) : FlowCachePlugin(plugin_options)
{
   print_stats = module_options.print_stats;
}

int TESTOVACIPLUGINPlugin::pre_create(Packet &pkt)
{
   return 0;
}

int TESTOVACIPLUGINPlugin::post_create(Flow &rec, const Packet &pkt)
{
   
   return 0;
}

int TESTOVACIPLUGINPlugin::pre_update(Flow &rec, Packet &pkt)
{
   return 0;
}

int TESTOVACIPLUGINPlugin::post_update(Flow &rec, const Packet &pkt)
{
   return 0;
}

void TESTOVACIPLUGINPlugin::pre_export(Flow &rec)
{
}

void TESTOVACIPLUGINPlugin::finish()
{
   if (print_stats) {
      //cout << "TESTOVACIPLUGIN plugin stats:" << endl;
   }
}

const char *ipfix_testovaciplugin_template[] = {
   IPFIX_TESTOVACIPLUGIN_TEMPLATE(IPFIX_FIELD_NAMES)
   NULL
};

const char **TESTOVACIPLUGINPlugin::get_ipfix_string()
{
   return ipfix_testovaciplugin_template;
}

string TESTOVACIPLUGINPlugin::get_unirec_field_string()
{
   return TESTOVACIPLUGIN_UNIREC_TEMPLATE;
}

bool TESTOVACIPLUGINPlugin::include_basic_flow_fields()
{
   return true;
}

