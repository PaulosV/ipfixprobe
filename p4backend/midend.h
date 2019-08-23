/**
 * \file midend.h
 * \brief Header file with class declaration of the compiler's midend
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

#ifndef _BACKENDS_P4E_MIDEND_H_
#define _BACKENDS_P4E_MIDEND_H_

#include "ir/ir.h"
#include "options.h"
#include "frontends/common/resolveReferences/referenceMap.h"
#include "frontends/p4/typeMap.h"

namespace P4E {

class MidEnd {
   std::vector<DebugHook> hooks;

public:
   P4::ReferenceMap refMap;
   P4::TypeMap typeMap;

   void addDebugHook(DebugHook hook) {
      hooks.push_back(hook);
   }
   const IR::ToplevelBlock *run(P4EOptions &options, const IR::P4Program *program);
};

} // namespace P4E
#endif // _BACKENDS_P4E_MIDEND_H_