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

#ifndef __MFT_ENTRYINFO_HH__
#define __MFT_ENTRYINFO_HH__

#include "ntfs_common.hpp"

class MFTEntryNode;
class MFTNode;

struct MFTId    //serializable
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
  uint64_t                      id;
  std::list<MFTId>              childrenId; //not use as we don't use the child method to link nodes
  MFTNode*                      node; //this is need to link other nodes and do final / directory linking  (can't link to an entry)
  std::list<MFTNode*>           nodes;//nodes for all $DATA attribute (unamed main $DATA and name ads)
  MFTEntryNode*                 entryNode(void) const;

  //static MFTEntryInfo*          fromDObject(DObject* object);  //load ?
  //static MFTEntryInfo*          load(Destruct::DValue const& args);
  Destruct::DObject*            save(void) const; //save ? 
private:
  MFTEntryNode*                 __entryNode; //entry is related to different node causes of ADS etc...
};

#endif
