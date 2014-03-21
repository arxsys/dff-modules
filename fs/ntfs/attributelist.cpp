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

#include <list>
#include <unicode/unistr.h>

#include "bootsector.hpp"
#include "ntfs.hpp"
#include "attributelist.hpp"
#include "mftattributecontent.hpp"
#include "mftattribute.hpp"
#include "mftentrynode.hpp"

/*
 *  AttributeListItems
 */

AttributeListItems::AttributeListItems(VFile* vfile)
{
  int32_t offset = vfile->read((void*)&this->__attributeList, sizeof(__attributeList)); 
  if (offset != sizeof(__attributeList))
    throw std::string("$ATTRIBUTE_LIST can't read AttributeList_s");
  
  if (this->__attributeList.nameSize > 0)
  {
    uint16_t* name = new uint16_t[this->__attributeList.nameSize];
    offset += vfile->read((void*)name, this->__attributeList.nameSize * sizeof(uint16_t));
    UnicodeString((char*)name, __attributeList.nameSize * sizeof(uint16_t), "UTF16-LE").toUTF8String(this->__name);
  }

  int32_t nextOffset = this->size() - offset;
  if (nextOffset > 0)
    vfile->seek(vfile->tell() + nextOffset); 
}

AttributeListItems::AttributeListItems(const AttributeListItems& copy) : __name(copy.__name), __attributeList(copy.__attributeList)
{
}

AttributeListItems::~AttributeListItems()
{
}

const std::string AttributeListItems::name(void) const
{
  return (this->__name);
}

uint32_t AttributeListItems::typeId(void) const
{
  return (this->__attributeList.typeId);
}

uint16_t AttributeListItems::size(void) const
{
  return (this->__attributeList.size);
}

uint64_t AttributeListItems::VCNStart(void) const
{
  return (this->__attributeList.VCNStart);
}

uint64_t AttributeListItems::mftEntryId(void) const
{
  uint64_t mftEntryId = 0;
  
  mftEntryId = *((uint32_t*)&this->__attributeList.mftEntryId);
  *((uint32_t*)&mftEntryId + 1) = *((uint16_t*)&this->__attributeList.mftEntryId + 2);

  return (mftEntryId);
}

uint16_t AttributeListItems::sequence(void) const
{
 return (*((uint16_t*)&this->__attributeList.sequence));
}

uint16_t AttributeListItems::attributeId(void) const
{
  return (this->__attributeList.attributeId);
}

/*
 *   AttributeList
 */

AttributeList::AttributeList(MFTAttribute* mftAttribute) : MFTAttributeContent(mftAttribute)
{
  VFile* vfile = this->open();

  while (vfile->tell() < this->size()) //&& vfile->tell() - this->size() >> sizeof(AttributeList_s) 
  {  //XXX check presvious == curent pour eviter loop inifi
    try
    {
      AttributeListItems attrib(vfile);
      this->__attributes.push_back(attrib);
    }
    catch (const std::string& error)
    {
    }
  }
  delete vfile;
}

std::vector<MFTAttribute*> AttributeList::MFTAttributes(void)
{
  std::vector<AttributeListItems>::iterator item = this->__attributes.begin();
  std::vector<MFTAttribute*> found;
  uint32_t MFTEntrySize = this->mftAttribute()->mftEntryNode()->ntfs()->bootSectorNode()->MFTRecordSize();
  for (; item != this->__attributes.end(); ++item)
  {
    MFTEntryNode* mftEntryNode = this->mftAttribute()->mftEntryNode();
    if (mftEntryNode->offset() == item->mftEntryId() * MFTEntrySize) 
      continue;
    MFTEntryNode* mft = new MFTEntryNode(mftEntryNode->ntfs(), mftEntryNode->mftNode(), item->mftEntryId() * MFTEntrySize, "", NULL);    
    std::vector<MFTAttribute*> attributes = mft->MFTAttributes(); 
    std::vector<MFTAttribute*>::iterator attribute = attributes.begin();
    //mft->updateState(); //? 
    //mftEntryNode->updateState();
    for (; attribute != attributes.end(); ++attribute)
    {
      if ((*attribute)->isResident())
      {
         //XXX
         std::cout << "create a resident attribute ? " << (*attribute)->typeId() << " " << item->typeId() << std::endl;
      }
      else if (((*attribute)->VNCStart() == item->VCNStart()) && ((*attribute)->typeId() == item->typeId()))
      {
        found.push_back(*attribute);
      }
    }
  }
 //XXX delete useless
  return (found);
}

MFTAttributeContent*	AttributeList::create(MFTAttribute* mftAttribute)
{
  return (new AttributeList(mftAttribute));
}

AttributeList::~AttributeList()
{
}

Attributes	AttributeList::_attributes(void)
{
  Attributes	attrs;

  MAP_ATTR("Attributes", MFTAttributeContent::_attributes());
  //XXX list attr fist ? defaultattr 
 
  //MAP_ATTR("Creation time", this->creationTime())
  //for attributes in MFTAttributes()
  return (attrs);
}

const std::string	AttributeList::typeName(void) const
{
  return (std::string("$ATTRIBUTE_LIST"));
}
