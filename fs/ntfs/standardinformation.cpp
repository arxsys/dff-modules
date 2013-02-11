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
#include "standardinformation.hpp"
#include "mftattributecontent.hpp"
#include "mftattribute.hpp"

#define PUSH_FLAGS(x, y)\
  if ((this->__standardInformation.flags & x) == x)\
    flagsList.push_back(NEW_VARIANT(std::string(y)));

#define READONLY  	0x0001
#define HIDDEN    	0x0002
#define SYSTEM 	  	0x0004
#define ARCHIVE	  	0x0020
#define DEVICE	  	0x0040
#define NORMAL	  	0x0080
#define TEMPORARY 	0x0100
#define SPARSE	  	0x0200
#define REPARSE	  	0x0400
#define COMPRESSED	0x0800
#define OFFLINE		0x1000
#define INDEXED		0x2000
#define ENCRYPTED	0x4000

StandardInformation::StandardInformation(MFTAttribute* mftAttribute) : MFTAttributeContent(mftAttribute)
{
  VFile*	vfile = NULL;
  
  vfile = this->open();
 
  if (vfile->read((void*)&(this->__standardInformation), sizeof(StandardInformation_s)) != sizeof(StandardInformation_s))
  {
    vfile->close();
    throw vfsError("Can't read attribute Standard Informations");
  }
  vfile->close();
}

MFTAttributeContent*	StandardInformation::create(MFTAttribute* mftAttribute)
{
	//std::cout << "StandardInformation::create new StandardInformation/MFTAttributeContent " << std::endl;
  return (new StandardInformation(mftAttribute));
}

StandardInformation::~StandardInformation()
{
//delete __StandardInformation ?? pourquoi c pas un pointeur ?
}

std::string	StandardInformation::typeName(void)
{
  return (std::string("$STANDARD_INFORMATION"));
}

Attributes	StandardInformation::_attributes(void)
{
  Attributes	attrs;

  MAP_ATTR("Creation time", this->creationTime())
  MAP_ATTR("Accessed time", this->accessedTime())
  MAP_ATTR("Altered time", this->alteredTime())
  MAP_ATTR("MFT altered time", this->mftAlteredTime())
  MAP_ATTR("flags", this->flags()) 
  MAP_ATTR("Max versions number", this->versionsMaximumNumber()) 
  MAP_ATTR("Version number", this->versionNumber())
  MAP_ATTR("Class ID", this->classID())
  MAP_ATTR("Owner ID", this->ownerID())
  MAP_ATTR("Security ID", this->securityID())
  MAP_ATTR("Quota charged", this->quotaCharged())
  MAP_ATTR("Update Sequence Number", this->USN())

  return (attrs);
}

vtime*		StandardInformation::creationTime(void)
{
  return (new vtime(this->__standardInformation.creationTime, TIME_MS_64));
}

vtime*		StandardInformation::alteredTime(void)
{
  return (new vtime(this->__standardInformation.alteredTime, TIME_MS_64));
}

vtime*		StandardInformation::mftAlteredTime(void)
{
  return (new vtime(this->__standardInformation.mftAlteredTime, TIME_MS_64));
}

vtime*		StandardInformation::accessedTime(void)
{
  return (new vtime(this->__standardInformation.accessedTime, TIME_MS_64));
}

std::list<Variant_p>	StandardInformation::flags(void)
{
  std::list<Variant_p > flagsList;

  PUSH_FLAGS(READONLY, "Read only");
  PUSH_FLAGS(HIDDEN, "Hidden");
  PUSH_FLAGS(SYSTEM, "System");
  PUSH_FLAGS(ARCHIVE, "Archive");
  PUSH_FLAGS(DEVICE, "Device");
  PUSH_FLAGS(NORMAL, "Normal");
  PUSH_FLAGS(TEMPORARY, "Temporary");
  PUSH_FLAGS(SPARSE, "Sparse");
  PUSH_FLAGS(REPARSE, "Reparse point");
  PUSH_FLAGS(COMPRESSED, "Compressed");
  PUSH_FLAGS(OFFLINE, "Offline");
  PUSH_FLAGS(INDEXED, "Content will not be indexed");
  PUSH_FLAGS(ENCRYPTED, "Encrypted");

  return (flagsList);
}

uint32_t	StandardInformation::versionsMaximumNumber(void)
{
  return (this->__standardInformation.versionsMaximumNumber);
}

uint32_t	StandardInformation::versionNumber(void)
{
  return (this->__standardInformation.versionNumber); 
}

uint32_t	StandardInformation::classID(void)
{
  return (this->__standardInformation.classID); 
}

uint32_t	StandardInformation::ownerID(void)
{
  return (this->__standardInformation.ownerID); 
}

uint32_t	StandardInformation::securityID(void)
{
  return (this->__standardInformation.securityID); 
}

uint64_t	StandardInformation::quotaCharged(void)
{
  return (this->__standardInformation.quotaCharged);
}

uint64_t	StandardInformation::USN(void)
{
  return (this->__standardInformation.USN); 
}