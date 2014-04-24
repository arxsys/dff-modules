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
MFTNode::MFTNode(NTFS* ntfs, MFTEntryNode* mftEntryNode) : Node("", 0, NULL, ntfs), __mftEntryNode(mftEntryNode)
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
        //if (mftEntryNode)
        //this->__mftEntryNode = new MFTEntryNode(*mftEntryNode);
  return (this->__mftEntryNode);
}

void                MFTNode::setName(const std::string name)
{
  this->__name = name;
}

Attributes	MFTNode::_attributes(void)
{
  if (this->__mftEntryNode != NULL)
    return (this->__mftEntryNode->_attributes());
  Attributes attr;
  return (attr);
}

void		MFTNode::fileMapping(FileMapping* fm)
{
  if (this->size() == 0)
    return;

  /* test : indexallocation filemapping */
  //std::vector<MFTAttribute*> indexAllocation = this->__mftEntryNode->MFTAttributesType($INDEX_ALLOCATION);
  //if (indexAllocation.size())
  //{
    //indexAllocation[0]->content()->fileMapping(fm);
    //return ;
  //}

  std::vector<MFTAttribute* >  datas = this->__mftEntryNode->data();
  std::vector<MFTAttribute*>::iterator data = datas.begin();
  for (; data != datas.end(); ++data)
  {
    MFTAttributeContent* dataContent = (*data)->content();
    dataContent->fileMapping(fm);
    delete (dataContent);
    delete (*data);
  }


  //if (this->mapMFT == true) show mft 
  //  this->__mftEntryNode->fileMapping(fm);
}
