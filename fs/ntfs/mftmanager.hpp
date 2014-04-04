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

#ifndef __MFT_MANAGER_HH__
#define __MFT_MANAGER_HH__

#include "ntfs_common.hpp"

class NTFS;
class MFTNode;

class MFTEntryInfo
{
public:
  MFTEntryInfo();
  uint64_t              id;
  std::list<uint64_t>   childrenId;
  bool                  linked; //node.parent() != null ? 
  MFTNode*              node;
  //unalocated          unallocatedMFT; mft is unalocated
  //std::list<uint64_t>   __unallocatedChildrenId; //index unaloted
};

class MFTEntryManager
{
public:
  MFTEntryManager(NTFS* ntfs, MFTNode* mftNode); 
  ~MFTEntryManager();
  void                                  initEntries(void);
  void                                  linkEntries(void);
  void                                  linkOrphanEntries(void); 
  void                                  childrenSanitaze(void);
  bool                                  add(uint64_t id, MFTNode* node);
  bool                                  add(uint64_t id, uint64_t childId);
  MFTNode*                              create(uint64_t id);
  bool                                  addChildId(uint64_t nodeId, MFTNode* node);
  bool                                  addChild(uint64_t nodeId);
  void                                  inChildren(uint64_t nodeId, uint64_t childId);
         
  uint64_t                              entryCount(void) const;  
  bool                                  exist(uint64_t id) const; 
  MFTNode*                              node(uint64_t id) const;
private:
  NTFS*                                 __ntfs;
  MFTNode*                              __masterMFTNode;
  std::map<uint64_t, MFTEntryInfo>      __entries;
  uint64_t                              __numberOfEntry;
};

#endif
