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

#ifndef __OBJECTID_HH__
#define __OBJECTID_HH__

#include "ntfs_common.hpp"
#include "mftattributecontent.hpp"

PACK_S ObjectId_s
{
  uint64_t      objectId[2];
  uint64_t      birthVolumeId[2];
  uint64_t      birthObjectId[2];
  uint64_t      birthDomainId[2];
} PACK;

class ObjectId : public MFTAttributeContent
{
public:
		        ObjectId(MFTAttribute* mftAttribute);
			~ObjectId();
  const std::string     objectId(void);
  const std::string     birthVolumeId(void);
  const std::string     birthObjectId(void);
  const std::string     birthDomainId(void);
  Attributes		_attributes(void);
  const std::string     typeName(void) const;
  static MFTAttributeContent*	create(MFTAttribute* mftAttribute);
private:
  const std::string      __objectIdToString(uint64_t* id);
  ObjectId_s             __objectId;
};

#endif
