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
#include "mftentrynode.hpp"

MFTNode::MFTNode(NTFS* ntfs, Node* mftFsNode, Node* parent, uint64_t offset) : Node("Unknown", 0, parent, ntfs)
{
  this->__mftEntryNode = new MFTEntryNode(ntfs, mftFsNode, offset, std::string("MFTEntry"), NULL);
  						//MFT_0xSectorNumber
  this->init();
}

MFTNode::MFTNode(NTFS* ntfs, Node* parent, MFTEntryNode* mftEntryNode) : Node("Unknown", 0, parent, ntfs)
{
 this->__mftEntryNode = mftEntryNode;
 this->init();
}

void	MFTNode::init(void)
{
//SET NAME !!!!
//There could be multiple filename we choose the lowest id file name who fit better

//une seul loop c plus optimiser 

  uint8_t fileNameID = FILENAME_NAMESPACE_DOS_WIN32;
  std::vector<MFTAttribute* > fileNames = this->__mftEntryNode->MFTAttributesType($FILE_NAME);
  std::vector<MFTAttribute* >::iterator currentFileName = fileNames.begin();

  for (; currentFileName != fileNames.end(); currentFileName++)
  {
    FileName*	fileName = static_cast<FileName* >((*currentFileName)->content());
    if (fileName->nameSpaceID() <= fileNameID) 
    {
      this->__name = fileName->name();
      fileNameID = fileName->nameSpaceID();
    }
  }
  //this->setSize(__mftEntryNode->dataCotentn()->size()
  //SET SIZE !!! XXX attention au ADS et au non-data 
  std::vector<MFTAttribute* > datas = this->__mftEntryNode->MFTAttributesType($DATA);
  if (datas.size() > 0) //XXX choisir le bon ds le init() ads tous ca tous ca
  {
    this->setSize(datas[0]->contentSize());
  }

}

MFTNode::~MFTNode()
{
// delete this->__mftEntryNode; // only if new here ?
}

Attributes	MFTNode::_attributes(void)
{
  return this->__mftEntryNode->_attributes();
}

void		MFTNode::fileMapping(FileMapping* fm)
{
 std::vector<MFTAttribute* > datas = this->__mftEntryNode->MFTAttributesType($DATA);
 if (datas.size() > 0) //XXX choisir le bon ds le init() ads tous ca tous ca
 {
    datas[0]->content()->fileMapping(fm);
 }
 else
//get the first data multi data for ads alternate data stream // create a new node here ! 
//ca peut etre ca ca auto-creer les ads ... la classe :) enfin plutot ds le 'init' si non ca va les creer au moment de demandede filemapping ...
  {
   cout << "NORMALLLL PUSH FUCK" << endl;
   this->__mftEntryNode->fileMapping(fm);
  }
}
