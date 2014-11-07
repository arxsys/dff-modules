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

#ifndef __NTFS_UNALLOCATED_HH__
#define __NTFS_UNALLOCATED_HH__

#include "ntfs_common.hpp"
#include "attributes/bitmap.hpp"

class NTFS;

class Unallocated : public Node
{
public:
  Unallocated(NTFS* ntfs);
  Unallocated(NTFS* ntfs, std::vector<Range> ranges, uint64_t size);
 
  void  fileMapping(FileMapping* fm);
  //Attributes	                       _attributes(void);
  std::vector<Range>  ranges(void);
  static Unallocated* load(NTFS* ntfs, Destruct::DValue const& arg);
  Destruct::DValue    save(void) const;
private:
  std::vector<Range>  __ranges;//for caving and recovery or must use large cache value for filemapping cache
  NTFS*               __ntfs;
};

#endif
