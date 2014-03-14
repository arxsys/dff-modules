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

#ifndef __NTFS_MFT_ENTRY_NODE_HH__
#define __NTFS_MFT_ENTRY_NODE_HH__

#include "ntfs_common.hpp"

class NTFS;
class MFTAttribute;

#define		MFT_SIGNATURE_FILE	0x454C4946
#define		MFT_SIGNATURE_BAAD	0x44414142

PACK_S	MFTEntry
{
  uint32_t	signature;
  uint16_t	fixupArrayOffset;
  uint16_t	fixupArrayEntryCount;
  uint64_t	LSN;
  uint16_t	sequenceValue;
  uint16_t	linkCount;
  uint16_t	firstAttributeOffset;
  uint16_t	flags;  //in use & directory  
  uint32_t	usedSize;
  uint32_t	allocatedSize;
  uint64_t	fileReferenceToBaseRecord;
  uint16_t	nextAttributeID;
} PACK;

class MFTEntryNode : public Node
{
private:
  NTFS*			__ntfs; 
  Node*			__fsNode;
  MFTEntry*		__MFTEntry;
  //uint32_t		__sectorNumber;
  uint64_t		__offset;
  uint64_t		__state;
  class MFTAttribute*	__MFTAttribute(uint16_t offset);
public:
			MFTEntryNode(NTFS* ntfs, Node* fsNode, uint64_t offset, std::string name, Node* parent);
			~MFTEntryNode();
  NTFS*			ntfs(void);
  Node*			fsNode(void);
  virtual uint64_t	fileMappingState(void);
  virtual void		fileMapping(FileMapping* fm);
  virtual uint64_t	_attributesState(void);
  virtual Attributes 	_attributes(void);
  uint64_t		offset(void);
  //uint64_t		sectorNumber(void);
  uint32_t		signature(void);
  uint32_t		usedSize(void);
  uint32_t		allocatedSize(void);
  void			validate(void);
  uint16_t		firstAttributeOffset(void);
  uint16_t		fixupArrayOffset(void);
  uint16_t		fixupArrayEntryCount(void);
//  uint16_t		fixupArraySignature(void); 
//  uint16_t*		fixupArrayBuffer(void);  
  std::vector<MFTAttribute* >	MFTAttributes();
  std::vector<MFTAttribute* >	MFTAttributesType(uint32_t typeID);
};

#endif
