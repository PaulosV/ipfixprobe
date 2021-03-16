/**
 * \file testovacipluginplugin.h
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

#ifndef TESTOVACIPLUGINPLUGIN_H
#define TESTOVACIPLUGINPLUGIN_H

#include <string>

#ifdef WITH_NEMEA
  #include "fields.h"
#endif

#include "flowifc.h"
#include "flowcacheplugin.h"
#include "packet.h"
#include "ipfixprobe.h"

using namespace std;

/**
 * \brief Flow record extension header for storing parsed TESTOVACIPLUGIN packets.
 */
struct RecordExtTESTOVACIPLUGIN : RecordExt {

   uint8_t possible_vpn;
   uint32_t sender_pubkey;
   uint32_t receiver_pubkey;

   RecordExtTESTOVACIPLUGIN() : RecordExt(testovaciplugin)
   {
   }

#ifdef WITH_NEMEA
   virtual void fillUnirec(ur_template_t *tmplt, void *record)
   {
      ur_set(tmplt, record, F_OVPN_CONF_LEVEL, possible_vpn);
   }
#endif

   virtual int fillIPFIX(uint8_t *buffer, int size)
   {
      return 0;
   }
};

/**
 * \brief Flow cache plugin for parsing TESTOVACIPLUGIN packets.
 */
class TESTOVACIPLUGINPlugin : public FlowCachePlugin
{
public:
   TESTOVACIPLUGINPlugin(const options_t &module_options);
   TESTOVACIPLUGINPlugin(const options_t &module_options, vector<plugin_opt> plugin_options);
   int pre_create(Packet &pkt);
   int post_create(Flow &rec, const Packet &pkt);
   int pre_update(Flow &rec, Packet &pkt);
   int post_update(Flow &rec, const Packet &pkt);
   void pre_export(Flow &rec);
   void finish();
   const char **get_ipfix_string();
   string get_unirec_field_string();
   bool include_basic_flow_fields();

private:
   RecordExtTESTOVACIPLUGIN *ext_ptr;  /**< Pointer to allocated record extension. */
   bool print_stats;       /**< Indicator whether to print stats when flow cache is finishing or not. */
   uint32_t total;         /**< Total number of SMTP packets seen. */
   uint32_t replies_cnt;   /**< Total number of SMTP replies. */
   uint32_t commands_cnt;  /**< Total number of SMTP commands. */
};

#endif

