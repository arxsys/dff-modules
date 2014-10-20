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
class MFTEntryNode;
class MFTEntryInfo;
class Unallocated;

using namespace Destruct;

class MFTEntryManager : public DCppObject<MFTEntryManager>
{
public:
  MFTEntryManager(DStruct* dstruct); 
  MFTEntryManager(DStruct* dstruct, DValue const& args); 
                                                ~MFTEntryManager();

  void                                          init(NTFS* ntfs);
  void                                          initEntries(void);
  void                                          linkEntries(void);
  void                                          linkOrphanEntries(void);
  void                                          linkReparsePoint(void) const;

  void                                          loadEntries(DValue const& value, Node* fsNode);
  DValue                              saveEntries(void) const;

  void                                          create(uint64_t id);
  MFTEntryInfo*                                 createFromOffset(uint64_t offset, Node* fsNode, int64_t id);

  bool                                          addChild(uint64_t nodeId);
  bool                                          addChildId(uint64_t nodeId, MFTNode* node);
  void                                          inChildren(uint64_t nodeId, uint64_t childId);
  void                                          childrenSanitaze(void);
         
  uint64_t                                      entryCount(void) const;  
  bool                                          exist(uint64_t id) const; 
  MFTNode*                                      node(uint64_t id) const;
  MFTEntryNode*                                 entryNode(uint64_t id) const;
  Node*                                         mapLink(MFTNode* node) const;

  void                                          searchUnallocated(Unallocated* unallocated);
  Unallocated*                                  createUnallocated(void);
  uint64_t                                      linkUnallocated(Unallocated* unallocated);
  MFTNode*                                      masterMFTNode(void) const;
private:
  NTFS*                                         __ntfs;
  MFTNode*                                      __masterMFTNode;
  uint64_t                                      __masterMFTOffset;
  uint64_t                                      __numberOfEntry;
  std::map<uint64_t, MFTEntryInfo*>             __entries; //DMap<a, at, b, ,bt>() ? 

  RealValue<DObject*>         __dentries;
  RealValue<DObject*>         __unallocatedOffset;
  RealValue<DFunctionObject*> __loadEntries;
  //RealValue<DFunctionObject*> __saveEntries;
public :
  static size_t ownAttributeCount()
  {
    return (1);
  }

  static DAttribute* ownAttributeBegin()
  {
    static DAttribute  attributes[] = 
    {
      DAttribute(DType::DObjectType,"unallocated"),
      //DAttribute(DType::DObjectType,"entries"),
     //DAttribute(DType::DNoneType, "loadEntries", DType::DObjectType),
      //DAttribute(DType::DObjectType,"saveEntries", DType::DNoneType),
    };
    return (attributes);
  }

  static DPointer<MFTEntryManager>* memberBegin()
  {
    static DPointer<MFTEntryManager> memberPointer[] = 
    {
      DPointer<MFTEntryManager>(&MFTEntryManager::__unallocatedOffset),
      //DPointer<MFTEntryManager>(&MFTEntryManager::__dentries),
      //DPointer<MFTEntryManager>(&MFTEntryManager::__loadEntries, &MFTEntryManager::loadEntries),
      //DPointer<MFTEntryManager>(&MFTEntryManager::__saveEntries, &MFTEntryManager::saveEntries),
    };
    return (memberPointer);
  }

  static DAttribute* ownAttributeEnd()
  {
    return (ownAttributeBegin() + ownAttributeCount());
  }

  static DPointer<MFTEntryManager >*  memberEnd()
  {
    return (memberBegin() + ownAttributeCount());
  }
};

#endif
