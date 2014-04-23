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

//#include <list>
//#include <unicode/unistr.h>
#include "reparsepoint.hpp"
#include "mftattributecontent.hpp"
#include "mftattribute.hpp"

#define PUSH_FLAGS(x, y)\
  if ((this->__reparsePoint.flags & x) == x)\
    flagsList.push_back(NEW_VARIANT(std::string(y)));

//#define READONLY  	0x0001
//#define HIDDEN    	0x0002

ReparsePoint::ReparsePoint(MFTAttribute* mftAttribute) : MFTAttributeContent(mftAttribute)
{
  VFile* vfile = this->open();
 
  if (vfile->read((void*)&(this->__reparsePoint), sizeof(ReparsePoint_s)) != sizeof(ReparsePoint_s))
  {
    delete vfile;
    throw vfsError("$REPARSE_POINT can't read ReparsePoint_s.");
  }
  vfile->seek(vfile->tell() + 1);
  std::string test;

  //std::cout <<"data name " <<  test << std::endl;  
  

  std::cout << "data type" << __reparsePoint.type <<
               " unused " << __reparsePoint.reserved <<
               " flags " << this->__reparsePoint.flags << 
               " size " << __reparsePoint.dataSize <<
               " targetsize  " << targetNameSize() << 
               " print size " << printNameSize() <<
               " buff size " << this->size() <<
               " target offset " << this->targetNameOffset() <<
               " print offset " << this->printNameOffset() <<
               std::endl;

  //uint16_t* name = new uint16_t[this->nameLength()];
  //if (vfile->read((void*)name, this->nameLength() * sizeof(uint16_t)) != (int32_t)(this->nameLength() *sizeof(uint16_t)))
  //{
  //delete[] name;
  //delete vfile;
  //throw vfsError("$REPARSE_POINT can't read name.");
  //}
  //UnicodeString((char*)name, this->nameLength() * sizeof(uint16_t), "UTF16-LE").toUTF8String(this->__name);
  //delete[] name;
  delete vfile;
}

MFTAttributeContent*	ReparsePoint::create(MFTAttribute*	mftAttribute)
{
  return (new ReparsePoint(mftAttribute));
}

ReparsePoint::~ReparsePoint()
{
}

Attributes	ReparsePoint::_attributes(void)
{
  Attributes	attrs;

  MAP_ATTR("Attributes", MFTAttributeContent::_attributes())

  MAP_ATTR("Target name", this->targetName())
  MAP_ATTR("print name", this->printName())
  MAP_ATTR("Flags", this->flags()) 

  return (attrs);
}

uint32_t ReparsePoint::dataSize(void) const
{
  return (this->__reparsePoint.dataSize);
}

uint16_t ReparsePoint::targetNameOffset(void) const
{
  return (this->__reparsePoint.targetNameOffset);
}

uint16_t ReparsePoint::targetNameSize(void) const
{
  return (this->__reparsePoint.targetNameSize);
}

uint16_t ReparsePoint::printNameOffset(void) const
{
  return (this->__reparsePoint.printNameOffset);
}

uint16_t ReparsePoint::printNameSize(void) const
{
  return (this->__reparsePoint.printNameSize);
}

const std::string  ReparsePoint::targetName(void) const
{
  return (this->__targetName);
}

const std::string  ReparsePoint::printName(void) const
{
  return (this->__printName);
}

const std::string  ReparsePoint::typeName(void) const
{
  return (std::string("$REPARSE_POINT"));
}

std::list<Variant_p>	ReparsePoint::flags(void) const
{
  std::list<Variant_p > flagsList;

  //PUSH_FLAGS(READONLY, "Read only");
  //PUSH_FLAGS(HIDDEN, "Hidden");
  //PUSH_FLAGS(SYSTEM, "System");
  //PUSH_FLAGS(ARCHIVE, "Archive");
  //PUSH_FLAGS(DEVICE, "Device");
  //PUSH_FLAGS(NORMAL, "Normal");
  //PUSH_FLAGS(TEMPORARY, "Temporary");
  //PUSH_FLAGS(SPARSE, "Sparse");
  //PUSH_FLAGS(REPARSE, "Reparse point");
  //PUSH_FLAGS(COMPRESSED, "Compressed");
  //PUSH_FLAGS(OFFLINE, "Offline");
  //PUSH_FLAGS(INDEXED, "Content will not be indexed");
  //PUSH_FLAGS(ENCRYPTED, "Encrypted");

  return (flagsList);
}