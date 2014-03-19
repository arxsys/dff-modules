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

#ifndef __ATTRIBUTE_LIST_HH__
#define __ATTRIBUTE_LIST_HH__

#include "ntfs_common.hpp"
#include "mftattributecontent.hpp"

PACK_S AttributeList_s 
{
  uint32_t      attributeType;
  uint16_t      recordLength;
  uint8_t       nameLength;
  uint8_t       offsetToName;
  uint64_t      startingVCN;
  uint64_t      baseFileReference;
  uint16_t      attributeId;
//name in unicode if name > 0 ? y a l offset de toute ?? 
} PACK;

class AttributeList : public MFTAttributeContent
{
private:
  AttributeList_s      __attributeList;
public:
		       AttributeList(MFTAttribute* mftAttribute);
		       ~AttributeList();
  Attributes           _attributes(void);
  const std::string    typeName(void) const;
  static MFTAttributeContent*	create(MFTAttribute* mftAttribute);
};

#endif
