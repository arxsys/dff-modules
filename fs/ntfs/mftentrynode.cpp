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

#include "ntfsopt.hpp"
#include "mftentrynode.hpp"
#include "bootsector.hpp"
#include "ntfs.hpp"
#include "mftmanager.hpp"
#include "mftattribute.hpp"
#include "mftattributecontent.hpp"
#include "attributes/mftattributecontenttype.hpp"

MFTNode::MFTNode(NTFS* ntfs, Node* mftNode, uint64_t offset, std::string name, Node* parent = NULL) : Node(name, ntfs->bootSectorNode()->MFTRecordSize(), parent, ntfs, false), __ntfs(ntfs), __mftNode(mftNode), __offset(offset), __state(0)
{
  if (this->__mftNode == NULL)
    throw std::string("MFTNode: Can't open MFT Node is null");
  VFile* vfile = this->__mftNode->open();
  if (vfile->seek(this->offset()) != this->offset())
  {
    delete vfile;
    throw std::string("Can't seek to MFT entry structure");
  }
  if  (vfile->read((void *)&this->__MFTEntry, sizeof(MFTEntry)) != sizeof(MFTEntry))
  {
    delete vfile;
    throw std::string("Can't read MFT Entry structure");
  }
  delete vfile;

  //this->validate(); for exemple when carving if wrong value avoid infinite loop etc... 
  //this->readAttributes();
  //for test only : read all attributes of the node 
}

/**
 *  For test only : read all attributs of the node
 */
void MFTNode::readAttributes(void)
{
  MFTAttributes mftAttributes = this->mftAttributes();
  MFTAttributes::iterator	mftAttribute;
  mftAttribute = mftAttributes.begin();
  for (; mftAttribute != mftAttributes.end(); ++mftAttribute)
  {
    try 
    {
      MFTAttributeContent* mftAttributeContent = (*mftAttribute)->content();//test content
      mftAttributeContent->_attributes();//test call attrib
      delete mftAttributeContent;
      if (*mftAttribute != NULL)
        delete (*mftAttribute);
    }
    catch (vfsError& e)
    {
      std::cout << "MFTNode::_attributes error: " << e.error << std::endl;
    }
    catch (std::string& e)
    {
      std::cout << "MFTNode::_attributes error: " << e << std::endl;
    }
  }
}


void MFTNode::updateState(void)
{
  this->__state++;
}

MFTNode::~MFTNode()
{
}

/** 
 *  Return all MFT Attributes of type typeId
 */
MFTAttributes	MFTNode::findMFTAttributes(uint32_t typeId)
{
  MFTAttributes		mftAttributesType;

  uint32_t offset = this->firstAttributeOffset();
  try 
  {
    //XXX this->useSize() != add all mft attributelist size 
    while (offset < this->usedSize()) 
    {   
       MFTAttribute* mftAttr = new MFTAttribute(this, offset);// this->__MFTAttribute(offset);
       if (mftAttr == NULL)
         break;
       uint64_t attributeLength = mftAttr->length();
       if (attributeLength == 0)
       {
         delete mftAttr;
         break;
       }
       if (mftAttr->typeId() == typeId)
         mftAttributesType.push_back(mftAttr);
       else
         delete mftAttr;
       offset += attributeLength;
    }
  }
  catch(std::string const& error)
  {
    //std::cout << "MFTAttribute error getting attribute " << error << std::endl;
  }

  return (mftAttributesType);
}


/**
 *  Return First MFTAttribute of type typeId 
 *  or NULL if not found
 */
MFTAttribute*	MFTNode::findMFTAttribute(uint32_t typeId)
{
  uint32_t offset = this->firstAttributeOffset();
  try 
  {
    //XXX this->useSize() != add all mft attributelist size 
    while (offset < this->usedSize()) 
    {   
       MFTAttribute* mftAttr = new MFTAttribute(this, offset);// this->__MFTAttribute(offset);
       if (mftAttr == NULL)
         break;
       uint64_t attributeLength = mftAttr->length();
       if (attributeLength == 0)
       {
         delete mftAttr;
         break;
       }
       if (mftAttr->typeId() == typeId)
         return (mftAttr);

       delete mftAttr;
       offset += attributeLength;
    }
  }
  catch(std::string const& error)
  {
    //std::cout << "MFTAttribute error getting attribute " << error << std::endl;
  }

  return (NULL);
}


/**
 *  Return all MFT Attributes
 */
MFTAttributes	MFTNode::mftAttributes(void)
{
  MFTAttributes	mftAttributes; 
  uint32_t offset = this->firstAttributeOffset();

  try 
  {
    //XXX this->useSize() != add all mft attributelist size 
    while (offset < this->usedSize()) 
    {   
       MFTAttribute* mftAttr = this->__MFTAttribute(offset);
       mftAttributes.push_back(mftAttr); 
       if (mftAttr->length() == 0) //check for other anormal size ? very big?
	 break;
       uint64_t attributeLength = mftAttr->length();
       if (attributeLength == 0)
         break;
       offset += attributeLength;
    }
  }
  catch(std::string const& error)
  {
    //std::cout << "MFTAttribute error getting attribute " << error << std::endl;
  }
  return (mftAttributes);
}

MFTAttribute*			MFTNode::__MFTAttribute(uint16_t offset)
{
  return (new MFTAttribute(this, offset));
}

void		MFTNode::fileMapping(FileMapping *fm)
{
  uint64_t offset = 0;
  uint16_t sectorSize = this->__ntfs->bootSectorNode()->bytesPerSector();

  while (offset < this->size())
  {
    if (this->size() - offset >= sectorSize)
    {
      fm->push(offset, sectorSize - sizeof(uint16_t), this->__mftNode, this->offset() + offset);
      offset += sectorSize - sizeof(uint16_t);
      fm->push(offset,
               sizeof(uint16_t),
               this->__mftNode,
	       this->offset() + this->fixupArrayOffset() + sizeof(uint16_t) + (sizeof(uint16_t) * (offset / sectorSize)));          
      offset += sizeof(uint16_t);
    }
    else
    {
      fm->push(offset, this->size() - offset, this->__mftNode, this->offset() + offset);
      offset += this->size() - offset;
    }
  }
}

uint64_t	MFTNode::_attributesState(void)
{
  return (this->__state);
}

uint64_t	MFTNode::fileMappingState(void)
{
  return (this->__state);
}

Attributes	MFTNode::_attributes(void)
{
  Attributes	attrs;

  if (this->__ntfs->opt()->advancedAttributes())
  { 
    MAP_ATTR("Entry id", this->offset() / this->ntfs()->bootSectorNode()->MFTRecordSize());
    MAP_ATTR("Offset", this->offset())
    MAP_ATTR("Signature", this->signature())
    MAP_ATTR("Used size", this->usedSize())
    MAP_ATTR("Allocated size", this->allocatedSize())
    MAP_ATTR("First attribute offset", this->firstAttributeOffset())
  }

  MFTAttributes            mftAttributes = this->mftAttributes();
  MFTAttributes::iterator  mftAttribute = mftAttributes.begin();
  for (; mftAttribute != mftAttributes.end(); ++mftAttribute)
  {
    try 
    {
      MFTAttributeContent* mftAttributeContent = (*mftAttribute)->content();
      //Special case
      //can have multi data so must name it differently or it will be overwritten !!!
      //if ((*mftAttribute)->typeID() == 32) //Special case a $ATTRIBUTE_LIST 
        //for i in mftattribute.MFTAttribute() MAP_ATTR
      MAP_ATTR(mftAttributeContent->typeName(), mftAttributeContent->_attributes());
      delete mftAttributeContent;
    }
    catch (vfsError& e)
    {
      std::cout << "MFTNode::_attributes error: " << e.error << std::endl;
    }
    catch (std::string& e)
    {
      std::cout << "MFTNode::_attributes error: " << e  << std::endl;
    }
    delete (*mftAttribute);
  }

  return (attrs);
}

void		MFTNode::validate(void) const
{
  if ((this->signature() != MFT_SIGNATURE_FILE) && (this->signature() != MFT_SIGNATURE_BAAD))
    throw std::string("MFT signature is invalid");
  // read & check fixup value  ...
}

NTFS*		MFTNode::ntfs(void) const
{
  return (this->__ntfs);
}

Node*		MFTNode::mftNode(void) const
{
  return (this->__mftNode);
}

uint64_t	MFTNode::offset(void) const
{
  return (this->__offset);
}

uint32_t	MFTNode::signature(void) const
{
  return (this->__MFTEntry.signature);
}

uint32_t	MFTNode::usedSize(void) const
{
  return (this->__MFTEntry.usedSize);
}

uint32_t	MFTNode::allocatedSize(void) const
{
  return (this->__MFTEntry.allocatedSize);
}

uint16_t        MFTNode::sequence(void) const
{
  return (this->__MFTEntry.sequence);
}

uint16_t	MFTNode::firstAttributeOffset(void) const
{
  return (this->__MFTEntry.firstAttributeOffset);
}

uint16_t	MFTNode::fixupArrayOffset(void) const
{
  return (this->__MFTEntry.fixupArrayOffset);
}

uint16_t        MFTNode::fixupArraySignature(void) const
{
  return (this->__MFTEntry.signature);
}

/* 
 * return count  -1 to skip signature 
*/
uint16_t	MFTNode::fixupArrayEntryCount(void) const
{
  return (this->__MFTEntry.fixupArrayEntryCount - 1);
}

bool            MFTNode::isUsed(void) const
{
  return (this->__MFTEntry.flags & 0x1);
}

bool            MFTNode::isDirectory(void) const
{
  return (this->__MFTEntry.flags & 0x2);
}

/**
 *  Search for best name in attribute
 */
const std::string   MFTNode::findName(void)
{
  uint8_t fileNameID = FILENAME_NAMESPACE_DOS_WIN32;
  std::string name;
  try 
  {
    MFTAttributes fileNames = this->findMFTAttributes($FILE_NAME);
    MFTAttributes::iterator currentFileName = fileNames.begin();

    for (; currentFileName != fileNames.end(); ++currentFileName)
    {
      FileName*	fileName = dynamic_cast<FileName* >((*currentFileName)->content());

      if (fileName == NULL)
      {
        //XXX delete all MFTAttribute before thrwoing !
        throw std::string("MFTNode can't cast attribute content to FileName");
      }
      if (fileName->nameSpaceID() <= fileNameID) 
      {
        name = fileName->name();
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
  
  return (name);
}

/**
 *  Serch for all $DATA attribute
 */
MFTAttributes      MFTNode::data(void)
{
  MFTAttributes dataAttributes = this->findMFTAttributes($DATA);

  MFTAttributes attributesLists = this->findMFTAttributes($ATTRIBUTE_LIST);
  MFTAttributes::iterator attributesList = attributesLists.begin();
  if (attributesLists.size() > 0) // in normal case there is only one attribute list 
  {
    AttributeList* attributeList = static_cast<AttributeList* >((*attributesList)->content());
    MFTAttributes attrs = attributeList->mftAttributes();
    MFTAttributes::iterator attr = attrs.begin();
      
    for (; attr != attrs.end(); ++attr)
    {
      if ((*attr)->typeId() == $DATA)
        dataAttributes.push_back(*attr);
      else
        delete (*attr);
    }
    delete (*attributesList);
  }
  return (dataAttributes);
}

//XXX use BITMAP !!!
std::vector<IndexEntry> MFTNode::indexes(void)// const 
{
  std::vector<IndexEntry> indexes;

  MFTAttributes indexRootAttributes = this->findMFTAttributes($INDEX_ROOT);
  MFTAttributes::iterator indexRootAttribute = indexRootAttributes.begin(); 

  if (indexRootAttributes.size() > 0)
  {
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

  MFTAttributes allocations = this->findMFTAttributes($INDEX_ALLOCATION);
  MFTAttributes::iterator  allocation = allocations.begin(); 
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
 
  MFTAttributes attributesLists = this->findMFTAttributes($ATTRIBUTE_LIST);
  MFTAttributes::iterator attributesList = attributesLists.begin();
  if (attributesLists.size() > 0) 
  {
    AttributeList* attributeList = static_cast<AttributeList* >((*attributesList)->content());
    MFTAttributes attrs = attributeList->mftAttributes();
    MFTAttributes::iterator attr = attrs.begin();
     
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
      delete (*attr);
    }
    delete attributeList;
    delete (*attributesList);
  }

  return (indexes);
}

Destruct::DValue        MFTNode::save(void) const
{
  Destruct::DObject* mftNode(Destruct::DStructs::instance().generate("MFTNode"));
  mftNode->setValue("offset", RealValue<DUInt64>(this->offset()));
  
  return (Destruct::RealValue<Destruct::DObject*>(mftNode)); 
}

MFTNode*        MFTNode::load(NTFS* ntfs, DValue const& value)
{
  DObject* mftNodeObject(value.get<DObject*>());
  DUInt64 offset = mftNodeObject->getValue("offset").get<DUInt64>();

  MFTNode* mftNode = new MFTNode(ntfs, ntfs->fsNode(), offset, "MFT", NULL);
  mftNodeObject->destroy();

  return (mftNode);
}

/**
 * MFTEntryNode
 */
MFTEntryNode::MFTEntryNode(NTFS* ntfs, DataNode* mftNode, uint64_t offset, std::string name, Node* parent) : MFTNode(ntfs, mftNode, offset, name, parent)
{
}

Destruct::DValue MFTEntryNode::save(void) const
{
  Destruct::DObject* mftEntryNode(Destruct::DStructs::instance().generate("MFTEntryNode"));
  DataNode* dataNode(static_cast<DataNode*>(this->mftNode()));

  mftEntryNode->setValue("offset", RealValue<DUInt64>(this->offset()));
  mftEntryNode->setValue("mftNodeOffset", RealValue<DUInt64>(dataNode->mftEntryNode()->offset()));

  return Destruct::RealValue<Destruct::DObject*>(mftEntryNode); 
}

MFTEntryNode*   MFTEntryNode::load(NTFS* ntfs, DValue const& value)
{
  DObject* mftEntryNodeObject(value.get<DObject*>());

  DUInt64 offset(mftEntryNodeObject->getValue("offset").get<DUInt64>());
  //DUInt64 mftOffset(mftEntryNodeObject->getValue("mftNodeOffset").get<DUInt64>()); //XXX use me ... or create DataNode
  MFTEntryNode* mftEntryNode(new MFTEntryNode(ntfs, ntfs->mftManager().masterMFTNode(), offset, "MFTEntry", NULL));
  mftEntryNodeObject->destroy();

  return (mftEntryNode);
}
