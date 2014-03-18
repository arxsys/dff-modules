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

#include "ntfs_common.hpp"
#include "ntfs.hpp"
#include "mftentrynode.hpp"
#include "filename.hpp"

#include "mftattributecontenttype.hpp"

MFTAttribute::MFTAttribute(MFTEntryNode* mftEntryNode, uint64_t offset) : __offset(offset), __mftEntryNode(mftEntryNode)
{
  this->__nonResidentAttribute = NULL;
  this->__residentAttribute = NULL;
  this->__mftAttribute = new MFTAttribute_s(); 

  VFile*  vfile = mftEntryNode->open();
  if (vfile->seek(offset) != offset)
  {
    delete vfile;
    throw std::string("MFT Attribute can't seek to attribute offset");
  }

  if (vfile->read((void*) this->__mftAttribute, sizeof(MFTAttribute_s)) != sizeof(MFTAttribute_s))
  {
    delete vfile;
    throw std::string("MFT Attribute can't read enough data");
  }

  if (this->typeID() == 0xffffffff)
  {
    delete vfile;
    throw std::string("End of attribute");
  }

  if (this->isResident())
  {
    this->__residentAttribute = new MFTResidentAttribute;
    if (vfile->read((void*) this->__residentAttribute, sizeof(MFTResidentAttribute)) != sizeof(MFTResidentAttribute))
    {
      delete vfile;
      throw std::string("MFT can't read resident attribute");
    }
  }
  else
  {
    this->__nonResidentAttribute = new MFTNonResidentAttribute;
    if (vfile->read((void*) this->__nonResidentAttribute, sizeof(MFTNonResidentAttribute)) != sizeof(MFTNonResidentAttribute))
      {
        delete vfile;
        throw std::string("MFT can't read resident attribute");
      }
  }
  delete vfile;
}

MFTAttribute::~MFTAttribute()
{
  if (this->__mftAttribute != NULL)
  {
    delete this->__mftAttribute;
    this->__mftAttribute = NULL;
  }
  if (this->__nonResidentAttribute != NULL)
  {
    delete this->__nonResidentAttribute;
    this->__nonResidentAttribute = NULL;
  }
  if (this->__residentAttribute != NULL)
  {
    delete this->__residentAttribute;
    this->__residentAttribute = NULL;
  }
}

MFTEntryNode*		MFTAttribute::mftEntryNode(void)
{
  return (this->__mftEntryNode);
}

//caller must delete AttributeCOntent !
// factory ...
MFTAttributeContent*	MFTAttribute::content(void)
{
  for (uint8_t	i = 0; ContentTypes[i].newObject != NULL; i++)
     if (ContentTypes[i].ID == this->typeID())
	return (ContentTypes[i].newObject(this));
    
  return (new MFTAttributeContent(this));
}

uint64_t 		MFTAttribute::contentSize(void)
{

  if (this->isResident())
    return (this->__residentAttribute->contentSize);

  if (this->__nonResidentAttribute->contentInitializedSize > this->__nonResidentAttribute->contentAllocatedSize)
      return (this->__nonResidentAttribute->contentActualSize);
  return (this->__nonResidentAttribute->contentInitializedSize);
}	

uint64_t		MFTAttribute::contentOffset(void)
{
  if (this->isResident())
    return (this->__offset + this->__residentAttribute->contentOffset);
  return (0);
}

uint16_t		MFTAttribute::runListOffset(void)
{
  if (!this->isResident())
    return (this->__nonResidentAttribute->runListOffset);
  throw std::string("Try to access non resident attribute on a resident attribute");
}
/*
std::string 		MFTAttribute::name()
{
  if (this->nameLength())
    return (std::string("attribute name found in self"));
  for (uint8_t	i = 0; ContentTypes[i].object != NULL; i++)
     if (ContentTypes[i].ID == this->typeID())
     {
	return ContentTypes[i].name;
     }
  return std::string("Unknown");
}
*/
uint64_t MFTAttribute::offset(void)
{
  return (this->__offset);
}

bool	MFTAttribute::isResident(void)
{
  return (!this->nonResidentFlag());
}

NTFS*	MFTAttribute::ntfs(void)
{
  return (this->__mftEntryNode->ntfs());
}

uint32_t MFTAttribute::typeID(void)
{
  return (this->__mftAttribute->typeID);
}

uint32_t MFTAttribute::length(void)
{
  return (this->__mftAttribute->length);
}

uint8_t	MFTAttribute::nonResidentFlag(void)
{
  return (this->__mftAttribute->nonResidentFlag);
}

uint8_t	MFTAttribute::nameLength(void)
{
  return (this->__mftAttribute->nameLength);
}

uint16_t MFTAttribute::nameOffset(void)
{
  return (this->__mftAttribute->nameOffset);
}

uint16_t MFTAttribute::flags(void)
{
  return (this->__mftAttribute->flags);
}

uint16_t MFTAttribute::ID(void)
{
  return (this->__mftAttribute->ID);
}

uint64_t MFTAttribute::VNCStart(void)
{
  return (this->__nonResidentAttribute->VNCStart);
}

uint64_t MFTAttribute::VNCEnd(void)
{
  return (this->__nonResidentAttribute->VNCEnd);
}

bool    MFTAttribute::isCompressed(void)
{
  return ((this->__mftAttribute->flags & 0x0001) == 0x0001);
}

bool    MFTAttribute::isEncrypted(void)
{
  return ((this->__mftAttribute->flags & 0x4000) == 0x4000);
}

bool    MFTAttribute::isSparse(void)
{
  return ((this->__mftAttribute->flags & 0x8000) == 0x8000);
}

