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

#ifndef __STANDARD_INFORMATION_HH__
#define __STANDARD_INFORMATION_HH__

#include "ntfs_common.hpp"
#include "mftattributecontent.hpp"

PACK_S StandardInformation_s
{
  uint64_t		creationTime;
  uint64_t		alteredTime;
  uint64_t		mftAlteredTime;
  uint64_t		accessedTime;
  uint32_t		flags;
  uint32_t		versionsMaximumNumber;
  uint32_t		versionNumber;
  uint32_t		classID;
  uint32_t		ownerID;
  uint32_t		securityID;
  uint64_t		quotaCharged;
  uint64_t		USN;
} PACK;

class StandardInformation : public MFTAttributeContent
{
private:
  StandardInformation_s	__standardInformation;
public:
		        StandardInformation(MFTAttribute* mftAttribute);
			~StandardInformation();
  vtime*		creationTime(void);
  vtime*		alteredTime(void);
  vtime*		mftAlteredTime(void);
  vtime*		accessedTime(void);
  std::list<Variant_p>	flags(void);
  uint32_t		versionsMaximumNumber(void);
  uint32_t		versionNumber(void);
  uint32_t		classID(void);
  uint32_t		ownerID(void);
  uint32_t		securityID(void);
  uint64_t		quotaCharged(void);
  uint64_t		USN(void);
  Attributes		_attributes(void);
  std::string		typeName(void);
  static MFTAttributeContent*	create(MFTAttribute* mftAttribute);
};

#endif
