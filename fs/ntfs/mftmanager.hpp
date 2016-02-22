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
class DataNode;
class MFTNode;
class MFTEntryInfo;
class Unallocated;

namespace DFF
{
class Node;
class VLink;
}

using namespace Destruct;
using namespace DFF;

class MFTEntryManager
{
public:
  MFTEntryManager(); 
  ~MFTEntryManager();

  void                                  init(NTFS* ntfs);
  void                                  initEntries(void);
  void                                  linkEntries(void);
  void                                  linkOrphanEntries(void);
  void                                  linkReparsePoint(void);// const;

  void                                  createEntry(DataNode* mftNode, uint64_t id);
  void                                  createEntry(Node* mftNode, uint64_t id);
  MFTEntryInfo*                         createFromOffset(uint64_t offset);
  MFTEntryInfo*                         createData(MFTNode* fsNode, int64_t id);

  bool                                  addChild(uint64_t nodeId);
  bool                                  addChildId(uint64_t nodeId, DataNode* node);
  void                                  inChildren(uint64_t nodeId, uint64_t childId);
  void                                  childrenSanitaze(void);
         
  uint64_t                              entryCount(void) const;  
  bool                                  exist(uint64_t id) const; 
  DataNode*                             node(uint64_t id) const;
  MFTNode*                              entryNode(uint64_t id) const;
  Node*                                 mapLink(DataNode* node); // const;

  void                                  searchUnallocated(Unallocated* unallocated);
  Unallocated*                          createUnallocated(void);
  uint64_t                              linkUnallocated(Unallocated* unallocated);
  DataNode*                             masterMFTNode(void) const;
  const std::vector<VLink*>&            vlinks(void) const;
private:
  NTFS*                                 __ntfs;
  DataNode*                             __masterMFTNode;
  uint64_t                              __masterMFTOffset;
  uint64_t                              __numberOfEntry;
  std::map<uint64_t, MFTEntryInfo*>     __entries; //useful ? < MFT, entryOffset, entryInfo ?>
  std::vector<VLink* >                  __vlinks; 
  std::vector<uint64_t >                __unallocatedOffsets;
  //RealValue<DObject*>                   __unallocatedOffset; //XXX XXX sert pu ! 
};

#endif
