#include "datetime.hpp"

#include "registry.hpp"
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

#include "registrynode.hpp"
#include "filemapping.hpp"

/**
 *  RegfNode
 */
RegfNode::RegfNode(DObject* regf, Registry* fsobj) : Node("", 0, NULL, fsobj)
{
  this->__name = regf->getValue("name").get<DUnicodeString>(); 
}

/**
 *  KeyNode
 */
KeyNode::KeyNode(DObject* key, Node* parent, Registry* fsobj) : Node("", 0, parent, fsobj)
{
  this->__name = key->getValue("name").get<DUnicodeString>();
  this->__timeStamp = key->getValue("timestamp"); 
}

Attributes      KeyNode::_attributes(void)
{
 Attributes attr;

 attr["modified"] = Variant_p(new Variant(new MS64DateTime(this->__timeStamp)));

 return (attr);
}

/**
 *  ValueNode
 */

ValueNode::ValueNode(DObject* value, Node* parent, Registry* fsobj) : Node("", 0, parent, fsobj)
{
  this->__name = value->getValue("name").get<DUnicodeString>();
  this->__dataType = value->getValue("dataType");
  this->__size = value->getValue("realDataSize").get<DInt32>();

  DObject* offsets = value->getValue("dataOffsets");
  DUInt64  offsetCount = offsets->call("size");
  for (DUInt64 index = 0; index < offsetCount; ++index)
  {
    DUInt32 offset = offsets->call("get", RealValue<DUInt64>(index));
    this->__offsets.push_back(offset);
  }
}

std::string  ValueNode::icon(void)
{
  return (":password.png");
}

Attributes      ValueNode::_attributes(void)
{
  Attributes attr;

  attr["type"] = Variant_p(new Variant(this->registryType(this->__dataType)));
//if type ...
//this->open->read() ?
  //attr["data"] = Variant_p(new Variant());

  return (attr);
}

void            ValueNode::fileMapping(FileMapping* fm)
{
  DUInt64 sizeReaded = 0;
  DUInt64 sizeToRead = 0;
  Node* rootNode = ((Registry*)this->__fsobj)->rootNode();

  if (((Registry*)this->__fsobj)->versionMinor() == 3 || this->__size < 16344)
  {
     fm->push(0, this->__size, rootNode, this->__offsets[0]);
     return ;
  }

  std::vector<uint64_t>::const_iterator offset = this->__offsets.begin();
  for (; offset != this->__offsets.end(); ++offset)
  {
    if (this->__size - sizeReaded < 16344)
      sizeToRead = this->__size - sizeReaded;
    else
      sizeToRead = 16344;
    if (this->__size > 16344)
      std::cout << sizeReaded << ' ' << sizeToRead << ' ' << *offset <<  std::endl; 
    fm->push(sizeReaded, sizeToRead, rootNode, *offset);
    sizeReaded += sizeToRead; 
  }
}
