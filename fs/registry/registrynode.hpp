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

#include "node.hpp"
#include "variant.hpp"
#include "dobject.hpp"

using namespace DFF;
using namespace Destruct;

class Registry;

class RegfNode : public Node
{
public:
  RegfNode(DObject* regf, Registry* fsobj);
};

class KeyNode : public Node
{
public:
  KeyNode(DObject* key, Node* parent, Registry* fsobj);
  Attributes _attributes(void);
private:
  DUInt64 __timeStamp;
};

class ValueNode : public Node
{
public:
  ValueNode(DObject* value, Node* parent, Registry* fsobj);
  std::string   icon(void);
  Attributes    _attributes(void);
  void          fileMapping(FileMapping* fm);
private:
  DUInt32       __dataType;
  std::vector<uint64_t> __offsets;

  static std::string registryType(uint32_t dataType)
  {
    static std::string registryType[] = { 
                                          "REG_NONE",
                                          "REG_SZ",
                                          "REG_EXPAND_SZ",
                                          "REG_BINARY",
                                          "REG_DWORD",
                                          "REG_DWORD_BIG_ENDIAN",
                                          "REG_LINK",
                                          "REG_MULTI_SZ",
                                          "REG_RESOURCE_LIST",
                                          "REG_FULL_RESOURCE_DESCRIPTON",
                                          "REG_RESOURCE_REQUIEREMENTS_LIST",
                                          "REG_QWORD",
                                        };
    if (dataType < 12) 
      return registryType[dataType]; 
    return ("REG_BINARY");
  }
};
