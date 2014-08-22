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
class Unallocated;

struct MFTId
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
  MFTEntryInfo(MFTEntryNode* entryNode);
  ~MFTEntryInfo();
  uint64_t              id;
  std::list<MFTId>      childrenId;
  MFTNode*              node; //this is need to link other nodes and do final / directory linking  (can't link to an entry)
  std::list<MFTNode*>   nodes;//nodes for all $DATA attribute (unamed main $DATA and name ads)
  MFTEntryNode*         entryNode(void) const;
private:
  MFTEntryNode*         __entryNode; //entry is related to different node causes of ADS etc...
};

class MFTEntryManager : public Destruct::DCppObject<MFTEntryManager>
{
public:
  MFTEntryManager(Destruct::DStruct* dstruct); 
  MFTEntryManager(Destruct::DStruct* dstruct, Destruct::DValue const& args); 
  ~MFTEntryManager();
  void                                  init(NTFS* ntfs);
  void                                  initEntries(void);
  void                                  linkEntries(void);
  void                                  linkOrphanEntries(void);
  void                                  linkReparsePoint(void) const;

  MFTEntryInfo*                         create(uint64_t id);
  MFTEntryInfo*                         createFromOffset(uint64_t offset, Node* fsNode, int64_t id);

  bool                                  addChild(uint64_t nodeId);
  bool                                  addChildId(uint64_t nodeId, MFTNode* node);
  void                                  inChildren(uint64_t nodeId, uint64_t childId);
  void                                  childrenSanitaze(void);
         
  uint64_t                              entryCount(void) const;  
  bool                                  exist(uint64_t id) const; 
  MFTNode*                              node(uint64_t id) const;
  MFTEntryNode*                         entryNode(uint64_t id) const;
  Node*                                 mapLink(MFTNode* node) const;

  void                                  searchUnallocated(Unallocated* unallocated);
  Unallocated*                          createUnallocated(void);
  uint64_t                              linkUnallocated(Unallocated* unallocated);
  MFTNode*                              masterMFTNode(void) const;
private:
  NTFS*                                 __ntfs;
  MFTNode*                              __masterMFTNode;
  uint64_t                              __masterMFTOffset;
  std::map<uint64_t, MFTEntryInfo*>     __entries;

//std::list<DUInt64_t offset>           __unallocated offset;
  uint64_t                              __numberOfEntry;
public :
  Destruct::RealValue<Destruct::DObject*>       unallocatedOffset;
  static size_t ownAttributeCount()
  {
    return (1);
  }

  static Destruct::DAttribute* ownAttributeBegin()
  {
    static Destruct::DAttribute  attributes[] = 
    {
      Destruct::DAttribute(Destruct::DType::DObjectType, "unallocated"),
    };
    return (attributes);
  }

  static Destruct::DPointer<MFTEntryManager>* memberBegin()
  {
    static Destruct::DPointer<MFTEntryManager> memberPointer[] = 
    {
      Destruct::DPointer<MFTEntryManager>(&MFTEntryManager::unallocatedOffset),
    };
    return (memberPointer);
  }

  static Destruct::DAttribute* ownAttributeEnd()
  {
    return (ownAttributeBegin() + ownAttributeCount());
  }

  static Destruct::DPointer<MFTEntryManager >*  memberEnd()
  {
    return (memberBegin() + ownAttributeCount());
  }
};

#endif
