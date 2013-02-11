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

MFTNode::~MFTNode(void)
{
  if (this->__mftEntryNode != NULL)
  {
     delete this->__mftEntryNode;
     this->__mftEntryNode = NULL;
  }
}

void	MFTNode::init(void)
{
  uint8_t fileNameID = FILENAME_NAMESPACE_DOS_WIN32;
 
  if (this->__mftEntryNode != NULL)
  {
    try 
    {
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
        delete fileName;
        delete (*currentFileName);
      }
    }
    catch (vfsError e)
    {
       std::cout << e.error << std::endl;
    }
    //this->setSize(__mftEntryNode->dataCotentn()->size()
    //SET SIZE !!! XXX warning ADS & non-data 
    std::vector<MFTAttribute* > datas = this->__mftEntryNode->MFTAttributesType($DATA);
    std::vector<MFTAttribute* >::iterator mftAttribute = datas.begin();

    if (datas.size() > 0) //XXX choose the right in init() because of ads ...
    {
      this->setSize(datas[0]->contentSize());
    }
    for (; mftAttribute != datas.end(); mftAttribute++)
      delete (*mftAttribute);
  }
}

Attributes	MFTNode::_attributes(void)
{
  if (this->__mftEntryNode != NULL)
    return this->__mftEntryNode->_attributes();
  Attributes attr;
  return attr; //throw error ?
}

void		MFTNode::fileMapping(FileMapping* fm)
{
  if (this->__mftEntryNode)
  {
    std::vector<MFTAttribute* > datas = this->__mftEntryNode->MFTAttributesType($DATA);
    std::vector<MFTAttribute* >::iterator mftAttribute;
    if (datas.size() > 0) //XXX choose the right in init because of ads ... 
    {
      MFTAttributeContent* mftAttributeContent = datas[0]->content();

      mftAttributeContent->fileMapping(fm);
      delete mftAttributeContent;
      for (mftAttribute = datas.begin(); mftAttribute != datas.end(); mftAttribute++)
	delete (*mftAttribute);
    }
    else
    {
      this->__mftEntryNode->fileMapping(fm);
    }
  }  
}
