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
#include "bitmap.hpp"

class NTFS;
class MFTNode;

class Unallocated : public Node
{
public:
  Unallocated(NTFS* ntfs);
  void  fileMapping(FileMapping* fm);
  //Attributes	                       _attributes(void);
  std::vector<Range>  ranges(void);
private:
  std::vector<Range>  __ranges; //test for carving et recovery car si non pu ds cache ? tres tres lent !
  NTFS*               __ntfs;
};

class MFTId
{
public:
  MFTId(uint64_t _id, uint16_t seq) : id(_id), sequence(seq) {};
  uint64_t id;
  uint16_t sequence;
  bool  operator ==(MFTId const& other)
  {
     if ((other.id == this->id) && (other.sequence == this->sequence))
       return true;
     return false;
  }

  bool  operator<(MFTId const& other)
  {
    if (other.id < this->id)
      return true;
    return false;
  }

};

class MFTEntryInfo
{
public:
  MFTEntryInfo(MFTNode* node);
  ~MFTEntryInfo();
  uint64_t              id;
//uint16_t              sequence;
  std::list<MFTId>      childrenId;
  MFTNode*              node;
};

class MFTEntryManager
{
public:
  MFTEntryManager(NTFS* ntfs, MFTNode* mftNode); 
  ~MFTEntryManager();
  void                                  initEntries(void);
  void                                  linkEntries(void);
  void                                  linkOrphanEntries(void);
  void                                  linkUnallocated(void);
 
  void                                  childrenSanitaze(void);
  MFTNode*                              create(uint64_t id);
  bool                                  add(uint64_t id, MFTNode* node); //??
  bool                                  addChild(uint64_t nodeId);//???
  bool                                  addChildId(uint64_t nodeId, MFTNode* node); //??
  void                                  inChildren(uint64_t nodeId, uint64_t childId);
         
  uint64_t                              entryCount(void) const;  
  bool                                  exist(uint64_t id) const; 
  MFTNode*                              node(uint64_t id) const;
private:
  NTFS*                                 __ntfs;
  MFTNode*                              __masterMFTNode;
  std::map<uint64_t, MFTEntryInfo*>     __entries;
  uint64_t                              __numberOfEntry;
};

#endif
