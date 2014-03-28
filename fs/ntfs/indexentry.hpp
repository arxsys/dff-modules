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

#ifndef __INDEX_ENTRY_HH__
#define __INDEX_ENTRY_HH__

#include <vector>

#include "ntfs_common.hpp"

PACK_S IndexEntry_s//spefici a filetype donc pour les entry ds indexallocation les indexrecord
{
  uint8_t       mftEntryId[6]; //file_ref + seq_number ? [6][2]
  uint16_t      sequence; 
  uint16_t      size;       //length of index entry
  uint16_t      contentSize; //$FILENAME ATTRIBUTE SIZE  //length of stream
  uint8_t       flags; //flags
  uint8_t       unknown[3];
  //uint8_t       stream; // ?? length of strlen ??
  //int8_t*     content[contentSize]
  //uint64_t    vnc; //-> content[contentSize] - 8
} PACK;

class IndexEntry
{
private:
  IndexEntry_s                  __indexEntry;
//int8_t*                       content;
  uint64_t                      __vcn;
public:
                                IndexEntry(VFile*);
  uint64_t                      mftEntryId(void) const;
  uint16_t                      size(void) const;
  uint16_t                      contentSize(void) const;
  uint32_t                      flags(void) const;
  bool                          isLast(void) const;
  bool                          haveChild(void) const;
//  uint8_t*                      content(void) const;
  uint64_t                      vcn(void) const;
};

class IndexEntries
{
private:
 std::vector<IndexEntry>        __entries;
public:
                IndexEntries(void);
 size_t         readEntries(VFile* vfile, uint32_t entriesStart, uint32_t entriesEnd);
 size_t         count(void) const;
};

#endif
