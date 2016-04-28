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

#include "datanode.hpp"
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
MFTEntryInfo::MFTEntryInfo(MFTNode* entryNode) : id(0), node(NULL), __entryNode(entryNode)
{
}

MFTEntryInfo::~MFTEntryInfo()
{
  //delete __entryNode;
  //__entryNode = NULL;
  //delete node & unlink
  //delete node; //node is always inserted dataNode and used as child for unallocated 

  //data node is used as child for unallocated
  //std::list<DataNode*>::iterator dataNode = this->nodes.begin();
  //for (; dataNode != this->nodes.end(); ++dataNode)
  //{
  //delete (*dataNode);
  //}
}

MFTNode*           MFTEntryInfo::entryNode(void) const
{
  return (this->__entryNode);
}
