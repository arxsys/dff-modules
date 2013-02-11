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
//XXX depend du constrcteur doit pas etre delte si passer par le 2eme constructeur ?
  if (this->__mftEntryNode != NULL)
  {
     delete this->__mftEntryNode;
     this->__mftEntryNode = NULL;
  }
}

void	MFTNode::init(void)
{
//SET NAME !!!!
//There could be multiple filename we choose the lowest id file name who fit better

//une seul loop c plus optimiser 

  uint8_t fileNameID = FILENAME_NAMESPACE_DOS_WIN32;
 
  if (this->__mftEntryNode != NULL)
  {
    try  //mis pour test arrive a lire un nom sur un fs mais peut raise et juste catch audessus de la node et pas la creee du tout
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
    //SET SIZE !!! XXX attention au ADS et au non-data 
    std::vector<MFTAttribute* > datas = this->__mftEntryNode->MFTAttributesType($DATA);
    std::vector<MFTAttribute* >::iterator mftAttribute = datas.begin();

    if (datas.size() > 0) //XXX choisir le bon ds le init() ads tous ca tous ca
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
    if (datas.size() > 0) //XXX choisir le bon ds le init() ads tous ca tous ca
    {
      MFTAttributeContent* mftAttributeContent = datas[0]->content();
//call sanas cache mais nous on est cache ?
      mftAttributeContent->fileMapping(fm);
      delete mftAttributeContent;
      for (mftAttribute = datas.begin(); mftAttribute != datas.end(); mftAttribute++)
	delete (*mftAttribute);
    }
    else
    //get the first data multi data for ads alternate data stream // create a new node here ! 
    //ca peut etre ca ca auto-creer les ads ... la classe :) enfin plutot ds le 'init' si non ca va les creer au moment de demandede filemapping ...
    {
//call sans cache mais nous on est dsle cache ?
      std::cout << "NORMALLLL PUSH " << std::endl;
      this->__mftEntryNode->fileMapping(fm);
    }
  }  
}
