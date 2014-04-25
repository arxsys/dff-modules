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
#include "mftnode.hpp"

class NTFS;
class MFTNode;

class MFTId
{
public:
  MFTId(uint64_t _id, uint16_t seq);
  bool  operator==(MFTId const& other);
  bool  operator<(MFTId const& other);

  uint64_t id;
  uint16_t sequence;
};

class MFTEntryInfo
{
public:
  MFTEntryInfo();
  ~MFTEntryInfo();
  uint64_t              id;
  //uint16_t            sequence;
  std::list<MFTId>      childrenId;
  MFTNode*              node; //this is need to link other nodes and do final / directory linking  (can't link to an entry)
  MFTEntryNode*         entryNode; //entry is related to different node causes of ADS etc...
  std::list<MFTNode*>   nodes;
};

class MFTEntryManager
{
public:
  MFTEntryManager(NTFS* ntfs); 
  ~MFTEntryManager();
  void                                  initEntries(void);
  void                                  linkEntries(void);
  void                                  linkOrphanEntries(void);
  void                                  linkUnallocated(void);

  MFTNode*                              create(uint64_t id);
  MFTNode*                              createFromOffset(uint64_t offset, Node* fsNode, int64_t id);

  //bool                                  add(uint64_t id, MFTNode* node);
  bool                                  addChild(uint64_t nodeId);
  bool                                  addChildId(uint64_t nodeId, MFTNode* node);
  void                                  inChildren(uint64_t nodeId, uint64_t childId);
  void                                  childrenSanitaze(void);
         
  uint64_t                              entryCount(void) const;  
  bool                                  exist(uint64_t id) const; 
  MFTNode*                              node(uint64_t id) const; //return main data node ? really usefull or return the entry ?
  MFTEntryNode*                         entryNode(uint64_t id) const;
private:
  NTFS*                                 __ntfs;
  MFTNode*                              __masterMFTNode;
  std::map<uint64_t, MFTEntryInfo*>     __entries;
  uint64_t                              __numberOfEntry;
};

#endif
