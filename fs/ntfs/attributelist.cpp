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

#include <list>
#include "attributelist.hpp"
#include "mftattributecontent.hpp"
#include "mftattribute.hpp"
#include "mftentrynode.hpp"

AttributeList::AttributeList(MFTAttribute* mftAttribute) : MFTAttributeContent(mftAttribute)
{
  std::cout << "Foud Attribute_list attribute in : " << mftAttribute->mftEntryNode()->name() <<  " size " << this->size() << std::endl;
  VFile* vfile = this->open();

  if (vfile->read((void*)&this->__attributeList, sizeof(__attributeList)) != sizeof(__attributeList))
  {
    delete vfile;
    throw std::string("$ATTRIBUTE_LIST can't read AttributeList_s");
  }
  delete vfile;
}

MFTAttributeContent*	AttributeList::create(MFTAttribute* mftAttribute)
{
  return (new AttributeList(mftAttribute));
}

AttributeList::~AttributeList()
{
}

Attributes	AttributeList::_attributes(void)
{
  Attributes	attrs;

  //MAP_ATTR("Parent directory reference", this->parentDirectoryReference());
  return (attrs);
}

const std::string	AttributeList::typeName(void) const
{
  return (std::string("$ATTRIBUTE_LIST"));
}
