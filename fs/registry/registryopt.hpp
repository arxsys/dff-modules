/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: *www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Solal Jacob <sja@digital-forensic.org>
 */

#ifndef __registry_opt_hh__
#define __registry_opt_hh__

#include "registry_common.hpp"

using namespace Destruct;

class RegistryOpt : public DCppObject<RegistryOpt>
{
public:
                RegistryOpt(Attributes args, DStruct* dstruct);
                RegistryOpt(Destruct::DStruct* dstruct, DValue const& args);
                ~RegistryOpt();
  Node*         fsNode(void) const;

  attributeCount(RegistryOpt, 1)
  attributeList(attribute(DObject, fsNode))
  memberList(RegistryOpt, member(RegistryOpt, __fsNode))
private:
  RealValue<DObject*>        __fsNode;
};

#endif
