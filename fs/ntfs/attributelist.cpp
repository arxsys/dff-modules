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
  if (mftAttribute->mftEntryNode())
    std::cout << "creating attribute List for " << mftAttribute->mftEntryNode()->name() <<  std::endl;
  else
    std::cout << "creating attribute List for mftattribute-EntryNode not found" <<  std::endl;
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

std::string	AttributeList::typeName(void)
{
  return (std::string("$ATTRIBUTE_LIST"));
}
