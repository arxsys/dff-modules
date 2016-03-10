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

#ifndef __DECOMPRESSOR_NODE_HH__
#define __DECOMPRESSOR_NODE_HH__

#include "node.hpp"

class Decompressor;
struct archive;

class DecompressorNode : public DFF::Node
{
public:
  DecompressorNode(std::string name, uint64_t size, Node* parent, Decompressor* decompressor);
  ~DecompressorNode();
//archive_entry_sourcepath
//archive_entry_size
//archive_entry_size_is_set
//archive_entry_atime_nsec
//archive_entry_atime
//archive_entry_atime_is_set
//archive_entry_birthtime
//archive_entry_birthtime_is_set
//archive_entry_ctime_nsec
//archive_entry_ctime_is_set
//archive_entry_mtime
//archive_entry_mtime_nsec
//archive_entry_mtime_is_set
//archive_entry_is_data_encrypted
//archive_entry_is_metadata_encrypted
//archive_entry_is_encrypted
//archive_entry_mac_metadata
//archive_entry_gname
};

#endif
