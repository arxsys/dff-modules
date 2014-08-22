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
class MFTEntryManager;
class Unallocated;

class NTFS : public mfso
{
private:
  NTFSOpt*              __opt;
  BootSectorNode*       __bootSectorNode;
  MFTEntryManager*      __mftManager;
  Node*                 __rootDirectoryNode;
  Node*                 __orphansNode;
  Unallocated*          __unallocatedNode;
public:
                        NTFS();
                        ~NTFS();

  static                void declare(void); // # XXX ///called from Python Module 

  void                  start(Attributes args);
  bool                  load(Destruct::DValue value);
  Destruct::DValue      save(void) const;

  void                  setStateInfo(const std::string&);
  NTFSOpt*              opt(void) const;
  Node*                 fsNode(void) const;
  Node*                 rootDirectoryNode(void) const;
  BootSectorNode*       bootSectorNode(void) const;
  Node*                 orphansNode(void) const;
  Unallocated*          unallocatedNode(void) const;
  MFTEntryManager*      mftManager(void) const;
  int32_t 	        vread(int fd, void *buff, unsigned int size);
};

class DNTFS : public Destruct::DCppObject<DNTFS>
{
public:
  DNTFS(Destruct::DStruct* dstruct, Destruct::DValue const& args);
  ~DNTFS();

  Destruct::RealValue<Destruct::DObject*>       opt, mftManager;
  static size_t ownAttributeCount()
  {
    return (2);
  }

  static Destruct::DAttribute* ownAttributeBegin()
  {
    static Destruct::DAttribute  attributes[] = 
    {
      Destruct::DAttribute(Destruct::DType::DObjectType, "opt"),
      Destruct::DAttribute(Destruct::DType::DObjectType, "mftManager"),
    };
    return (attributes);
  }

  static Destruct::DPointer<DNTFS>* memberBegin()
  {
    static Destruct::DPointer<DNTFS> memberPointer[] = 
    {
      Destruct::DPointer<DNTFS>(&DNTFS::opt),
      Destruct::DPointer<DNTFS>(&DNTFS::mftManager),
    };
    return (memberPointer);
  }

  static Destruct::DAttribute* ownAttributeEnd()
  {
    return (ownAttributeBegin() + ownAttributeCount());
  }

  static Destruct::DPointer<DNTFS >*  memberEnd()
  {
    return (memberBegin() + ownAttributeCount());
  }
};

#endif
