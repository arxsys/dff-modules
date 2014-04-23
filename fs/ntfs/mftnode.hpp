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

#ifndef __NTFS_MFT_HH__
#define __NTFS_MFT_HH__

#include "ntfs_common.hpp"
#include "mftentrynode.hpp"
#include "indexroot.hpp"

class NTFS;
class MFTEntryNode;
class MFTAttributeContent;

class MFTNode : public Node //public MFTEntryNode ?
{
public:
  MFTNode(NTFS*	ntfs, Node* mftFsNode, Node* parent, uint64_t sectorNumber);
  ~MFTNode();
  void		                       init(void);
  MFTEntryNode*                        mftEntryNode(void);
  std::vector<MFTAttribute*>           data(void) const;
  std::vector<IndexEntry>              indexes(void) const;
  const std::string                    findName(void) const;
  //void                                 setMapping(uint64_t attributes, uint64_t size); //attributes attributeList ? 
  void                                 setName(const std::string name);

  Attributes	                       _attributes(void);
  void		                       fileMapping(FileMapping* fm);
private:
  MFTEntryNode*	                       __mftEntryNode;
};

#endif
