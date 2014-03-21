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
 //this->__name = "MFTNode" + std::string(offset);
  this->__mftEntryNode = new MFTEntryNode(ntfs, mftFsNode, offset, std::string("MFTEntry"), NULL);
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
  if (!this->__mftEntryNode->isUsed()) //not sufficient need $BITMAP ? check & compare
    this->setDeleted();
  if (this->__mftEntryNode->isDirectory())
    this->setDir();
  else
    this->setFile();

  /*
   *  Search for name attribute to set node name
   */
  ///XXX 
  uint8_t fileNameID = FILENAME_NAMESPACE_DOS_WIN32;
  if (this->__mftEntryNode != NULL)
  {
    try 
    {
      std::vector<MFTAttribute* > fileNames = this->__mftEntryNode->MFTAttributesType($FILE_NAME);
      std::vector<MFTAttribute* >::iterator currentFileName = fileNames.begin();

      for (; currentFileName != fileNames.end(); ++currentFileName)
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
    catch (vfsError& e)
    {
       std::cout << e.error << std::endl;
    }

    /*
     *  search $DATA in attribute to set node size
     */
    std::vector<MFTAttribute* > datas = this->__mftEntryNode->MFTAttributesType($DATA);
    std::vector<MFTAttribute* >::iterator mftAttribute = datas.begin();
    if (datas.size() > 0) //XXX add ADS in new node 
    {
      this->setSize(datas[0]->contentSize());
    }
    for (; mftAttribute != datas.end(); ++mftAttribute)
      delete (*mftAttribute);

    /*
     *  search for $DATA in attributeList to set node size
     */
    //search for sub attribut in mftattributestype ? 
    std::vector<MFTAttribute* > attributesLists = this->__mftEntryNode->MFTAttributesType($ATTRIBUTE_LIST);
    std::vector<MFTAttribute* >::iterator attributesList = attributesLists.begin();
    //XXX test on only one attribute list -> maybe can have other ?
    if (attributesLists.size() > 0) //XXX add ADS in new node 
    {
      AttributeList* attributeList = static_cast<AttributeList* >((*attributesList)->content());
      std::vector<MFTAttribute* > attrs = attributeList->MFTAttributes();
      std::vector<MFTAttribute* >::iterator attr = attrs.begin();
       
      for (; attr != attrs.end(); ++attr)
      {
         if ((*attr)->typeId() == $DATA)
         {
           this->setSize((*attr)->contentSize()); //ca a pas l air d etre la bonne size :)
           //XXX ok pour celui la mais check si pas ads etc... 

           break;
         }
      }
    }
    for (; attributesList != attributesLists.end(); ++attributesList)
      delete (*attributesList);
  }
}

Attributes	MFTNode::_attributes(void)
{
  if (this->__mftEntryNode != NULL)
    return (this->__mftEntryNode->_attributes());
  Attributes attr;
  return attr;
}

void		MFTNode::fileMapping(FileMapping* fm)
{
 int flag = 0; 
  if (this->__mftEntryNode)
  {
//file can have multi filemapping please remember that 
    std::vector<MFTAttribute* > datas = this->__mftEntryNode->MFTAttributesType($DATA);
    std::vector<MFTAttribute* >::iterator mftAttribute;
    if (datas.size() > 0) //XXX choose the right in init because of ads ... 
    {
      MFTAttributeContent* mftAttributeContent = datas[0]->content();
      mftAttributeContent->fileMapping(fm);
      delete mftAttributeContent;
      for (mftAttribute = datas.begin(); mftAttribute != datas.end(); ++mftAttribute)
	delete (*mftAttribute);
      return ;
    }

    std::vector<MFTAttribute* > attributesLists = this->__mftEntryNode->MFTAttributesType($ATTRIBUTE_LIST);
    std::vector<MFTAttribute* >::iterator attributesList = attributesLists.begin();
    if (attributesLists.size() > 0) 
    {
      AttributeList* attributeList = static_cast<AttributeList* >((*attributesList)->content());
      std::vector<MFTAttribute* > attrs = attributeList->MFTAttributes();
      std::vector<MFTAttribute* >::iterator attr = attrs.begin();
      
      for (; attr != attrs.end(); ++attr)
      {
         if ((*attr)->typeId() == $DATA)
         {
          MFTAttributeContent* mftAttributeContent = (*attr)->content();
          //if (flag == 1)
          mftAttributeContent->fileMapping(fm); //add offset already pushed !
          flag += 1;
          //XXX delete et check filemapping pour attributeList & ntfs normal car editeur hexa boucle a l infi surcertains fichier ! 
          //delete mftAttributeContent;
          //for (mftAttribute = datas.begin(); mftAttribute != datas.end(); ++mftAttribute)
          //delete (*mftAttribute);
          //return ;
        }
      }
    }
    //for (; attributesList != attributesLists.end(); ++attributesList)
    //delete (*attributesList);
    if (flag == 0)
      this->__mftEntryNode->fileMapping(fm);//setSize to mftSize by default is not set !
  }
}
