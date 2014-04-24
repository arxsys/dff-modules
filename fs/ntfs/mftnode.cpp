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

#include <vector>

#include "mftnode.hpp"
#include "ntfs.hpp"
#include "mftattributecontenttype.hpp"

//MFTNode::MFTNode(NTFS* ntfs, MFTEntryNode& mftEntryNode) : MFTEntryNode(mftEntryNode)//Node("", 0, NULL, ntfs)
MFTNode::MFTNode(NTFS* ntfs, MFTEntryNode* mftEntryNode) : Node("", 0, NULL, ntfs), __mftEntryNode(mftEntryNode), __isCompressed(false)
{
}

MFTNode::~MFTNode(void)
{
  if (this->__mftEntryNode != NULL)
  {
    //delete this->__mftEntryNode; //used by ads ?
    this->__mftEntryNode = NULL;
  }
}

MFTEntryNode* MFTNode::mftEntryNode(MFTEntryNode* mftEntryNode)
{
  return (this->__mftEntryNode);
}

void                MFTNode::setName(const std::string name)
{
  this->__name = name;
}

void            MFTNode::setMappingAttributes(MappingAttributesInfo const&  mappingAttributesInfo)
{
  this->mappingAttributesOffset = mappingAttributesInfo.mappingAttributes;
  this->__isCompressed = mappingAttributesInfo.compressed;
  this->setSize(mappingAttributesInfo.size);
}

void		MFTNode::fileMapping(FileMapping* fm)
{
  if (this->size() == 0)
    return;

  std::list<MappingAttributes >::iterator attributeOffset = this->mappingAttributesOffset.begin();
  for (; attributeOffset != this->mappingAttributesOffset.end(); ++attributeOffset)
  {
    MappingAttributes ma = *attributeOffset;
    MFTAttribute* data = ma.entryNode->__MFTAttribute(ma.offset);
    MFTAttributeContent* content = data->content();
    content->fileMapping(fm);
    delete data;
    delete content;   
  } 
}

Attributes	MFTNode::_attributes(void)
{
  if (this->__mftEntryNode != NULL)
    return (this->__mftEntryNode->_attributes());
  Attributes attr;
  return (attr);
}
