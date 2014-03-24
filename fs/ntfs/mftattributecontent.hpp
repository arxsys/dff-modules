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

#ifndef __MFT_ATTRIBUTE_CONTENT_HH__
#define __MFT_ATTRIBUTE_CONTENT_HH__

#include <iostream>
#include <vector> 

#include "ntfs_common.hpp"

class MFTAttribute;

struct RunListInfo 
{
  union 
  {
     uint8_t byte;
     struct {
	      uint8_t lengthSize:4;
	      uint8_t offsetSize:4;
     	    } info;
  };
};

struct RunList
{
  int64_t    offset; //in cluster
  uint64_t   length;
};

#define NTFS_TOKEN_MASK   1
#define NTFS_SYMBOL_TOKEN 0
#define NTFS_TOKEN_LENGTH 8
/* (64 * 1024) = 65536 */
#define NTFS_MAX_UNCOMPRESSION_BUFFER_SIZE 65536

class CompressionInfo
{
public:
  CompressionInfo(uint64_t runSize);
  ~CompressionInfo();
  char *uncomp_buf;           // Buffer for uncompressed data
  char *comp_buf;             // buffer for compressed data
  size_t comp_len;            // number of bytes used in compressed data
  size_t uncomp_idx;          // Index into buffer for next byte
  size_t buf_size_b;          // size of buffer in bytes (1 compression unit)
};

class MFTAttributeContent : public Node
{
public:
  			        MFTAttributeContent(MFTAttribute* mftAttribute);
	 		        ~MFTAttributeContent();
  Attributes		        _attributes();
  MFTAttribute*                 mftAttribute(void);
  void			        fileMapping(FileMapping* fm);
  std::string		        attributeName(void) const;
  virtual const std::string	typeName(void) const;
  std::vector<RunList>          runList(void); //private & store for speed ? 
  uint64_t                      uncompress(uint64_t offset, uint8_t* buff, uint64_t size);
  uint64_t                      uncompressBlock(VFile* fs, RunList run, char** data, CompressionInfo* comp, uint64_t* lastValidOffset);
  void                          uncompressUnit(CompressionInfo* comp); 
private:
  MFTAttribute*	                __mftAttribute;
};

#endif
