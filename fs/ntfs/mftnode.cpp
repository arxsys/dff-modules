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
#include "mftattributecontent.hpp"
#include "mftattributecontenttype.hpp"
#include "mftentrynode.hpp"

MFTNode::MFTNode(NTFS* ntfs, Node* mftFsNode, Node* parent, uint64_t offset) : Node("", 0, parent, ntfs)
{
  this->__mftEntryNode = new MFTEntryNode(ntfs, mftFsNode, offset, std::string("MFTEntry"), NULL);
  this->__mftEntryNode->updateState();
  this->init();

  if (this->__name == "")
  {
    std::ostringstream name; 
    name << "Unknown-" << offset;
    this->__name = name.str();
  }
}

MFTNode::~MFTNode(void)
{
  if (this->__mftEntryNode != NULL)
  {
    delete this->__mftEntryNode;
    this->__mftEntryNode = NULL;
  }
}

MFTEntryNode* MFTNode::mftEntryNode(void)
{
  return (this->__mftEntryNode);
}

void MFTNode::setName(const std::string name)
{
  this->__name = name;
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
        FileName*	fileName = dynamic_cast<FileName* >((*currentFileName)->content());

        if (fileName == NULL)
          throw std::string("MFTNode can't cast attribute content to FileName");
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
 
   //XXX use indexallocation attribute as node data for directory
    //std::vector<MFTAttribute*> indexAllocation = this->__mftEntryNode->MFTAttributesType($INDEX_ALLOCATION);
    //if (indexAllocation.size())
    //{
      //this->setSize(indexAllocation[0]->content()->size());
      //return ;
    //}

    /*
     *  search $DATA in attribute to set node size
     */
    std::vector<MFTAttribute* > datas = this->__mftEntryNode->MFTAttributesType($DATA);
    std::vector<MFTAttribute* >::iterator data = datas.begin();
    if (datas.size() > 0) //XXX add ADS in new node 
    {
      this->setSize((*data)->contentSize());
    }
    for (; data != datas.end(); ++data)
      delete (*data);

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
           this->setSize((*attr)->contentSize());
           break;
         }
         delete (*attr);
      }
      for (; attr != attrs.end(); ++attr)
        delete (*attr);
      delete attributeList;
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
  return (attr);
}

std::vector<MFTAttribute*>      MFTNode::data(void)
{
  std::vector<MFTAttribute*> dataAttributes;

  if (this->__mftEntryNode)
  {
    std::vector<MFTAttribute* > datas = this->__mftEntryNode->MFTAttributesType($DATA);
    std::vector<MFTAttribute* >::iterator mftAttribute = datas.begin();
    if (datas.size() > 0) //XXX choose the right one because of ADS 
    {
      MFTAttribute* dataAttribute = datas[0];
      dataAttributes.push_back(dataAttribute);

      for (++mftAttribute; mftAttribute != datas.end(); ++mftAttribute)
        delete (*mftAttribute);
      return (dataAttributes); //attribute is not deleted != attributeContent 
    }

    std::vector<MFTAttribute* > attributesLists = this->__mftEntryNode->MFTAttributesType($ATTRIBUTE_LIST);
    std::vector<MFTAttribute* >::iterator attributesList = attributesLists.begin();
    if (attributesLists.size() > 0) // in normal case there is only one attribute list 
    {
      AttributeList* attributeList = static_cast<AttributeList* >((*attributesList)->content());
      std::vector<MFTAttribute* > attrs = attributeList->MFTAttributes();
      std::vector<MFTAttribute* >::iterator attr = attrs.begin();
      
      for (; attr != attrs.end(); ++attr)
      {
        if ((*attr)->typeId() == $DATA)
          dataAttributes.push_back(*attr);
        else
          delete (*attr);
      }
      delete (*attributesList);
    }
  }
  return (dataAttributes);
}

//XXX use BITMAP !!!
std::vector<IndexEntry> MFTNode::indexes(void) //indexesFilename // don't return objectIds, securityDescriptor ...
{
  std::vector<IndexEntry> indexes;

  std::vector<MFTAttribute*> indexRootAttributes = this->__mftEntryNode->MFTAttributesType($INDEX_ROOT);
  std::vector<MFTAttribute*>::iterator indexRootAttribute = indexRootAttributes.begin(); 

  if (indexRootAttributes.size() > 0)
  {
    //if (indexRootAttributes.size() > 1)
        //std::cout << "MFT entry has more than one ROOT attribute " << std::endl;
    IndexRoot* indexRoot = dynamic_cast<IndexRoot*>((*indexRootAttribute)->content());
    if (indexRoot)
    {
      std::vector<IndexEntry> info = indexRoot->indexEntries();
      if (indexRoot->indexType() != $FILE_NAME) //Only handle $FILE_NAME index for now
      {
        delete indexRoot;
        for (;indexRootAttribute != indexRootAttributes.end(); ++indexRootAttribute)
          delete (*indexRootAttribute);
        return (indexes);
      }
      indexes.insert(indexes.end(), info.begin(), info.end());
      delete indexRoot;
    }
    for (;indexRootAttribute != indexRootAttributes.end(); ++indexRootAttribute)
       delete (*indexRootAttribute);
  }
  else 
    return (indexes);

  std::vector<MFTAttribute*> allocations = this->__mftEntryNode->MFTAttributesType($INDEX_ALLOCATION);
  std::vector<MFTAttribute*>::iterator  allocation = allocations.begin(); 
  for (; allocation != allocations.end(); ++allocation)
  {
    IndexAllocation* indexAllocation = dynamic_cast<IndexAllocation* >((*allocation)->content());
    if (indexAllocation)
    {
      std::vector<IndexEntry> info = indexAllocation->indexEntries();
      indexes.insert(indexes.end(), info.begin(), info.end());    
      delete indexAllocation;
    }
    delete (*allocation);
  }
 
  std::vector<MFTAttribute* > attributesLists = this->__mftEntryNode->MFTAttributesType($ATTRIBUTE_LIST);
  std::vector<MFTAttribute* >::iterator attributesList = attributesLists.begin();
  if (attributesLists.size() > 0) 
  {
    AttributeList* attributeList = static_cast<AttributeList* >((*attributesList)->content());
    std::vector<MFTAttribute* > attrs = attributeList->MFTAttributes();
    std::vector<MFTAttribute* >::iterator attr = attrs.begin();
     
    //if (attributesLists.size() > 1)
    //std::cout << "more than one attributes list found in index" << std::endl;  

    for (; attr != attrs.end(); ++attr)
    {
      if ((*attr)->typeId() == $INDEX_ALLOCATION)
      {
        IndexAllocation* indexAllocation = dynamic_cast<IndexAllocation* >((*attr)->content());
        if (indexAllocation)
        {
          std::vector<IndexEntry> info = indexAllocation->indexEntries();
          indexes.insert(indexes.end(), info.begin(), info.end());    
          delete indexAllocation;
        }
      }
      //else if ((*attr)->typeId() == $INDEX_ROOT)
        //this shouldn't happen
      delete (*attr);
    }
    delete attributeList;
    delete (*attributesList);
  }

  return (indexes);
}

void		MFTNode::fileMapping(FileMapping* fm)
{
  /* test : indexallocation filemapping */
  //std::vector<MFTAttribute*> indexAllocation = this->__mftEntryNode->MFTAttributesType($INDEX_ALLOCATION);
  //if (indexAllocation.size())
  //{
    //indexAllocation[0]->content()->fileMapping(fm);
    //return ;
  //}
  std::vector<MFTAttribute* >  datas = this->data();
  if (datas.size() == 0)
  {
    this->__mftEntryNode->fileMapping(fm);
    return;
  }
  std::vector<MFTAttribute*>::iterator data = datas.begin();
  for (; data != datas.end(); ++data)
  {
    MFTAttributeContent* dataContent = (*data)->content();
    dataContent->fileMapping(fm);
    delete (dataContent);
    delete (*data);
  }
}
