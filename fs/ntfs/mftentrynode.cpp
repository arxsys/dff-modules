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

#include "mftentrynode.hpp"
#include "bootsector.hpp"
#include "ntfs.hpp"
#include "mftattribute.hpp"
#include "mftattributecontent.hpp"

MFTEntryNode::MFTEntryNode(NTFS* ntfs, Node* mftNode, uint64_t offset, std::string name, Node* parent = NULL) : Node(name, ntfs->bootSectorNode()->MFTRecordSize(), parent, ntfs), __ntfs(ntfs), __mftNode(mftNode), __offset(offset), __state(0)
{
  VFile* vfile = NULL;
  vfile = this->__mftNode->open();
  if (vfile->seek(this->offset()) != this->offset())
  {
    delete vfile;
    throw std::string("Can't seek to MFT entry structure");
  }
  this->__MFTEntry = new MFTEntry; 
  if  (vfile->read((void *)this->__MFTEntry, sizeof(MFTEntry)) != sizeof(MFTEntry))
  {
    delete vfile;
    delete this->__MFTEntry;  
    throw std::string("Can't read MFT Entry structure");
  }
  delete vfile;

//  this->validate(); exemple ds le carving ou ca pete car decallage donc rajouter du checking 
//  if carving done des mauvais result ...

  //test : read all attributes of the node 
  std::vector<MFTAttribute* > mftAttributes = this->MFTAttributes();
  std::vector<MFTAttribute* >::iterator	mftAttribute;
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
                  std::cout << "MFTEntryNode::_attributes error: " << e.error << std::endl;
          }
          catch (std::string& e)
          {
                  std::cout << "MFTEntryNode::_attributes error: " << e << std::endl;
          }
  }
  this->__state++;
}

void MFTEntryNode::updateState(void)
{
  this->__state++;
}

MFTEntryNode::~MFTEntryNode()
{
  if (this->__MFTEntry != NULL)
  {
    delete this->__MFTEntry;
    this->__MFTEntry = NULL;
  }
}

std::vector<MFTAttribute*>	MFTEntryNode::MFTAttributesType(uint32_t typeId)
{
  std::vector<MFTAttribute* >		mftAttributesType;
  std::vector<MFTAttribute* >		mftAttributes;
  std::vector<MFTAttribute* >::iterator	mftAttribute;

  mftAttributes = this->MFTAttributes();
  mftAttribute = mftAttributes.begin();
  for (; mftAttribute != mftAttributes.end(); ++mftAttribute)
    if ((*mftAttribute)->typeId() == typeId)
      mftAttributesType.push_back(*mftAttribute);
    else
      delete (*mftAttribute);
  return (mftAttributesType);
}

std::vector<MFTAttribute*>	MFTEntryNode::MFTAttributes(void)
{
  std::vector<MFTAttribute*>	mftAttributes; 
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
       {
         std::cout << "erropr attribute length 0 " << std::endl;
         break;
       }
       offset += attributeLength;
    }
  }
  catch(std::string const& error)
  {
    //std::cout << "MFTAttribute error getting attribute " << error << std::endl;
  }
  return (mftAttributes);
}

MFTAttribute*			MFTEntryNode::__MFTAttribute(uint16_t offset)
{
  return (new MFTAttribute(this, offset));
}

void		MFTEntryNode::fileMapping(FileMapping *fm)
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

uint64_t	MFTEntryNode::_attributesState(void)
{
  return (this->__state);
}

uint64_t	MFTEntryNode::fileMappingState(void)
{
  return (this->__state);
}

Attributes	MFTEntryNode::_attributes(void)
{
  Attributes	attrs;

  MAP_ATTR("Entry id", this->offset() / this->ntfs()->bootSectorNode()->MFTRecordSize());
  MAP_ATTR("Offset", this->offset())
  MAP_ATTR("Signature", this->signature())
  MAP_ATTR("Used size", this->usedSize())
  MAP_ATTR("Allocated size", this->allocatedSize())
  MAP_ATTR("First attribute offset", this->firstAttributeOffset())

  std::vector<MFTAttribute*>		mftAttributes = this->MFTAttributes();
  std::vector<MFTAttribute*>::iterator  mftAttribute = mftAttributes.begin();
  for (; mftAttribute != mftAttributes.end(); ++mftAttribute)
  {
    try 
    {
      MFTAttributeContent* mftAttributeContent = (*mftAttribute)->content();
      //if ((*mftAttribute)->typeId() == 128) //Special case a $DATA as no attribute 
      //can have multi data so must name it differently or it will be overwritten !!!
      //if ((*mftAttribute)->typeID() == 32) //Special case a $ATTRIBUTE_LIST 
        //for i in mftattribute.MFTAttribute() MAP_ATTR
      MAP_ATTR(mftAttributeContent->typeName(), mftAttributeContent->_attributes());
      delete mftAttributeContent;
      delete (*mftAttribute);
    }
    catch (vfsError& e)
    {
      std::cout << "MFTEntryNode::_attributes error: " << e.error << std::endl;
    }
    catch (std::string& e)
    {
      std::cout << "MFTEntryNode::_attributes error: " << e  << std::endl;
    }
  }
  //delete  attribute map;

  return (attrs);
}

void		MFTEntryNode::validate(void) const
{
  if ((this->signature() != MFT_SIGNATURE_FILE) && (this->signature() != MFT_SIGNATURE_BAAD))
    throw std::string("MFT signature is invalid");
  // read & check fixup value  ...
}

NTFS*		MFTEntryNode::ntfs(void)
{
  return (this->__ntfs);
}

Node*		MFTEntryNode::mftNode(void)
{
  return (this->__mftNode);
}

uint64_t	MFTEntryNode::offset(void) const
{
  return (this->__offset);
}

uint32_t	MFTEntryNode::signature(void) const
{
  if (this->__MFTEntry != NULL)
    return (this->__MFTEntry->signature);
  throw std::string("ntfs::MFTEntryNode::signature no MFTEntry.");
}

uint32_t	MFTEntryNode::usedSize(void) const
{
  if (this->__MFTEntry != NULL)
    return (this->__MFTEntry->usedSize);
  throw std::string("ntfs::MFTEntryNode::useSize no MFTEntry.");
}

uint32_t	MFTEntryNode::allocatedSize(void) const
{
  if (this->__MFTEntry != NULL)
    return (this->__MFTEntry->allocatedSize);
  throw std::string("ntfs::MFTEntryNode::allocatedSize no MFTEntry.");
}

uint16_t        MFTEntryNode::sequence(void) const
{
  if (this->__MFTEntry != NULL)
    return (this->__MFTEntry->sequence);
  throw std::string("NTFS::MFTEntryNode no MFT Entry.");
}

uint16_t	MFTEntryNode::firstAttributeOffset(void) const
{
  if (this->__MFTEntry != NULL) 
    return (this->__MFTEntry->firstAttributeOffset);
  throw std::string("ntfs::MFTEntryNode::attributeOffset no MFTEntry.");
}

uint16_t	MFTEntryNode::fixupArrayOffset(void) const
{
  if (this->__MFTEntry != NULL) 
    return (this->__MFTEntry->fixupArrayOffset);
  throw std::string("ntfs::MFTEntryNode::fixupArrayOffset no MFTEntry.");
}

uint16_t        MFTEntryNode::fixupArraySignature(void) const
{
  if (this->__MFTEntry != NULL)
    return (this->__MFTEntry->signature);
  throw std::string("ntfs::MFTEntryNode::fixupArraySignature no MFTEntry.");
}

/* 
 * return count  -1 to skip signature 
*/
uint16_t	MFTEntryNode::fixupArrayEntryCount(void) const
{
  if (this->__MFTEntry != NULL) 
    return (this->__MFTEntry->fixupArrayEntryCount - 1);
  throw std::string("ntfs::MFTEntryNode::fixupArratEntryCount no MFTEntry.");
}

bool            MFTEntryNode::isUsed(void) const
{
  if (this->__MFTEntry != NULL)
    return (this->__MFTEntry->flags & 0x1);
  throw std::string("ntfs::MFTEntryNode::isUsed no MFTEntry."); 
}

bool            MFTEntryNode::isDirectory(void) const
{
  if (this->__MFTEntry != NULL)
    return (this->__MFTEntry->flags & 0x2);
  throw std::string("ntfs::MFTEntryNode::isDirectory no MFTEntry."); 
}
