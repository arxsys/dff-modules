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

PACK_S	MFTNonResidentAttribute
{
  uint64_t	VNCStart; // if present address de la prochaie mft avec la suite de l attribut
  uint64_t	VNCEnd;
  uint16_t	runListOffset;
  uint16_t	compressionUnitSize;
  uint32_t	unused1;
  uint64_t	contentAllocatedSize;
  uint64_t	contentActualSize;
  uint64_t	contentInitializedSize;
} PACK;

PACK_S  MFTAttribute_s
{
  uint32_t	typeID;
  uint32_t	length;
  uint8_t	nonResidentFlag;
  uint8_t	nameLength;
  uint16_t	nameOffset;
  uint16_t	flags;
  uint16_t	ID;
} PACK;

class MFTAttribute
{
private:
  uint64_t			__offset;
  MFTEntryNode*			__mftEntryNode;
  MFTAttribute_s*		__mftAttribute; //pas en pointeur /read buff +- 1024
  MFTNonResidentAttribute*	__nonResidentAttribute; // cast buff offset
  MFTResidentAttribute*		__residentAttribute;//  cast buff offset
public:
		        MFTAttribute(MFTEntryNode* ntfsNode, uint64_t offset);//vfile pour pas reopen ?
		        ~MFTAttribute(void);
  MFTEntryNode*		mftEntryNode(void);
  uint64_t		offset(void);
  uint32_t		typeID(void);
  uint32_t		length(void);
  bool			isResident(void);
  uint8_t		nonResidentFlag(void);
 //std::string		name(void); //mis ds content pour les special case comme filename qui existe plusieurs fois et doit avoir un nom ds attribute (au moins) different
  uint8_t		nameLength(void);
  uint16_t		nameOffset(void);
  uint16_t		flags(void); //compressed encrypter sparse ! spare a verifier pour le read du content ? 
  uint16_t		ID(void);
  NTFS*			ntfs();
  MFTAttributeContent*  content(void);
  uint64_t		contentOffset(void);
  uint64_t		contentSize(void);
  uint16_t		runListOffset(void);
};

#endif

