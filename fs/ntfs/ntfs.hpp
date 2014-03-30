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

#ifndef __NTFS_HH__
#define __NTFS_HH__

#include "ntfs_common.hpp"

class NTFSOpt;
class BootSectorNode;
class MFTNode;

class MFTEntryInfo
{
public:
  uint64_t              id;
  //unalocated          unallocatedMFT; mft is unalocated
  std::list<uint64_t>   childrenId;
  //std::list<uint64_t>   __unallocatedChildrenId; //index unaloted
  bool                  linked; //node.parent() != null ? 
  MFTNode*              node;
};

class MFTEntryManager
{
public:
            MFTEntryManager(void); 
            //MFTEntryManager(offset, id); //create a master MFT comme ca on peut en gerer plusieurs (MFT MIRROR OU carved MFT) 
            
  bool      exist(uint64_t id);  
  bool      add(uint64_t id, MFTNode* node);
  bool      add(uint64_t id, uint64_t childId);
  bool      addChildId(uint64_t nodeId, MFTNode* node);
  bool      addChild(uint64_t nodeId);
  void      inChildren(uint64_t nodeId, uint64_t childId);
  void      childrenSanitaze(void);
  MFTNode*  node(uint64_t id);
private:
  std::map<uint64_t, MFTEntryInfo>              __entries;
};

class NTFS : public mfso
{
private:
  MFTEntryManager       __mftManager;

  NTFSOpt*              __opt;
  Node*                 __rootDirectoryNode;
  Node*                 __orphansNode;
  BootSectorNode*       __bootSectorNode;
public:
                        NTFS();
                        ~NTFS();
  virtual void          start(Attributes args);
  void                  setStateInfo(const std::string&);
  NTFSOpt*              opt(void) const;
  Node*                 fsNode(void) const;
  Node*                 rootDirectoryNode(void) const;
  BootSectorNode*       bootSectorNode(void) const;
  /*
   *  Need file mapping && bufer read for decompression
   */
  int32_t 	        vread(int fd, void *buff, unsigned int size);
};

#endif
