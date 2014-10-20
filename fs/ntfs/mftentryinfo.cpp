/* DFF -- An Open Source Digital Forensics Framework
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

//#include "mftmanager.hpp"
//#include "ntfs.hpp"
//#include "ntfsopt.hpp"
//#include "bootsector.hpp"
//#include "unallocated.hpp"
//#include "attributes/mftattributecontenttype.hpp"
//
#include "mftentryinfo.hpp"

#include "mftnode.hpp"
#include "mftentrynode.hpp"

/**
 *  MFTId
 */
MFTId::MFTId(uint64_t _id, uint16_t seq) : id(_id), sequence(seq) 
{
}

bool  MFTId::operator==(MFTId const& other)
{
  if ((other.id == this->id) && (other.sequence == this->sequence))
    return (true);
  return (false);
}

bool  MFTId::operator<(MFTId const& other)
{
  if (other.id < this->id)
    return (true);
  return (false);
}

/**
 *  MFTEntryInfo
 */
MFTEntryInfo::MFTEntryInfo(MFTEntryNode* entryNode) : id(0), node(NULL), __entryNode(entryNode)
{
}

MFTEntryInfo::~MFTEntryInfo()
{
//delete node & unlink
}

MFTEntryNode*           MFTEntryInfo::entryNode(void) const
{
  return (this->__entryNode);
}

Destruct::DObject*      MFTEntryInfo::save(void) const
{
  Destruct::Destruct& destruct = Destruct::Destruct::instance();
  Destruct::DObject* dmftEntry = destruct.generate("MFTEntryInfo");
  Destruct::DObject* dnodes = destruct.generate("DVectorObject");

  //++nodes; HEIN ???? c surcharger ou ca ?
  dmftEntry->setValue("id", Destruct::RealValue<DUInt64>(this->id));
  if (this->node)
    dmftEntry->setValue("node", Destruct::RealValue<Destruct::DObject*>(this->node->save())); //XXX verifie qu il n y est pas 2 ref ! 
  for (std::list<MFTNode*>::const_iterator mftNode = this->nodes.begin(); mftNode != this->nodes.end(); ++mftNode)
  {
    if (*mftNode)
      dnodes->call("push", Destruct::RealValue<Destruct::DObject*>((*mftNode)->save()));
  }
  dmftEntry->setValue("nodes", Destruct::RealValue<Destruct::DObject*>(dnodes)); 
  dmftEntry->setValue("entryNode", Destruct::RealValue<DUInt64>(this->__entryNode->offset()));
  ///XXX MFTid List ? ?? not used yet  
 
  return (dmftEntry);
}

//XXX si c pas usefull why ?

//MFTEntryInfo*   MFTEntryInfo::load(Destruct::DValue const& args)
//{
  //Destruct::DObject* dmftEntryInfo = args.get<Destruct::DObject*>();

  ////mftEntryInfo->addAttribute(Destruct::DAttribute(Destruct::DType::DUInt64Type, "id"));
  ////mftEntryInfo->addAttribute(Destruct::DAttribute(Destruct::DType::DObjectType, "childrenId"));
  ////mftEntryInfo->addAttribute(Destruct::DAttribute(Destruct::DType::DObjectType, "node"));
  ////mftEntryInfo->addAttribute(Destruct::DAttribute(Destruct::DType::DObjectType, "nodes"));

  ////mftEntryInfo->addAttribute(Destruct::DAttribute(Destruct::DType::DUInt64Type, "entryNode"));
  ////DUInt64 entryNodeOffset = mftEntryInfo.getValue("entryNode")->get<DUInt64>();
  ////
  ////MFTEntryNode(mftEntryManager->ntfs(), mftEntryManager->masterMFTNode(), entryNode->offset, std::string("MFTEntry"), NULL);
  ////
  ////dmftEntryInfo->destroy();
  

  //return new MFTEntryInfo(0);
//}
