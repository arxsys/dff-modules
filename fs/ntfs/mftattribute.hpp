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

#ifndef __MFT_ATTRIBUTE_HH__
#define __MFT_ATTRIBUTE_HH__

#include "ntfs_common.hpp"

class NTFS;
class MFTEntryNode;
class MFTAttributeContent;

PACK_S	MFTResidentAttribute
{
  uint32_t	contentSize;
  uint16_t	contentOffset;
} PACK;

//faire un union entre nonresident et resident evite de gerer 2 struct
PACK_S	MFTNonResidentAttribute
{
  uint64_t	VNCStart;
  uint64_t	VNCEnd;
  uint16_t	runListOffset;
  uint16_t	compressionUnitSize;
  uint32_t	unused1;
  uint64_t	contentAllocatedSize; //size round up to cluster size if compressed multi[ple of compression blocksize
  uint64_t	contentActualSize;   //uncompressed size if compressed
  uint64_t	contentInitializedSize; //compressed size if compressed else actual/real size !
} PACK;

PACK_S  MFTAttribute_s
{
  uint32_t	typeID;
  uint32_t	length;
  uint8_t	nonResidentFlag;
  uint8_t	nameLength;
  uint16_t	nameOffset;
  uint16_t	flags;  //compressed flags
  uint16_t	ID; //union en dessous
} PACK;

class MFTAttribute
{
private:
  uint64_t			__offset;
  MFTEntryNode*			__mftEntryNode;
  MFTAttribute_s*		__mftAttribute;
  MFTNonResidentAttribute*	__nonResidentAttribute; // cast buff offset
  MFTResidentAttribute*		__residentAttribute;//  cast buff offset
public:
		        MFTAttribute(MFTEntryNode* mftEntryNode, uint64_t offset);
		        ~MFTAttribute(void);
  MFTEntryNode*		mftEntryNode(void);
  uint64_t		offset(void);
  uint32_t		typeID(void);
  uint32_t		length(void);
  bool			isResident(void);
  uint8_t		nonResidentFlag(void);
 //std::string		name(void); 
  uint8_t		nameLength(void);
  uint16_t		nameOffset(void);
  uint16_t		flags(void); 
  uint16_t		ID(void);
  NTFS*			ntfs();
  MFTAttributeContent*  content(void);
  uint64_t		contentOffset(void);
  uint64_t		contentSize(void);
  uint16_t		runListOffset(void);
  uint64_t              VNCStart(void);
  uint64_t              VNCEnd(void);
  bool                  isCompressed(void);
  bool                  isSparse(void);
  bool                  isEncrypted(void);
};

#endif

