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
#include "mftmanager.hpp"

class NTFSOpt;
class BootSectorNode;
class DataNode;
class Unallocated;

using namespace Destruct;

#define NTFS_VERSION 1

class DNTFS : public DCppObject<DNTFS>
{
public:
  DNTFS(DStruct* dstruct, DValue const& args);
  ~DNTFS();

  RealValue<DObject*>       opt, entries, reparsePoints;

  static size_t ownAttributeCount()
  {
    return (4);
  }

  static DAttribute* ownAttributeBegin()
  {
    static DAttribute  attributes[] = 
    {
      DAttribute(DType::DUInt8Type, "version"),
      DAttribute(DType::DObjectType, "opt"),
      DAttribute(DType::DObjectType, "entries"),
      DAttribute(DType::DObjectType, "reparsePoints"),
    };
    return (attributes);
  }

  static DPointer<DNTFS>* memberBegin()
  {
    static DPointer<DNTFS> memberPointer[] = 
    {
      DPointer<DNTFS>(&DNTFS::__version),
      DPointer<DNTFS>(&DNTFS::opt),
      DPointer<DNTFS>(&DNTFS::entries),
      DPointer<DNTFS>(&DNTFS::reparsePoints),
    };
    return (memberPointer);
  }

  static DAttribute* ownAttributeEnd()
  {
    return (ownAttributeBegin() + ownAttributeCount());
  }

  static DPointer<DNTFS >*  memberEnd()
  {
    return (memberBegin() + ownAttributeCount());
  }
private:
  RealValue<DUInt8>         __version;
};

class NTFS : public DFF::mfso
{
private:
  MFTEntryManager       __mftManager;
  NTFSOpt*              __opt;
  BootSectorNode*       __bootSectorNode;
  DFF::Node*            __rootDirectoryNode;
  DFF::Node*            __orphansNode;
  Unallocated*          __unallocatedNode;
public:
                        NTFS();
                        ~NTFS();

  static                void declare(void); // # XXX ///called from Python Module 

  void                  start(DFF::Attributes args);
  bool                  load(DValue value);
  DValue                save(void) const;
  DObject*              saveTree(Node* node) const;
  Node*                 loadTree(DValue const& args); 

  void                  setStateInfo(const std::string&);
  NTFSOpt*              opt(void) const;
  DFF::Node*            fsNode(void) const;
  DFF::Node*            rootDirectoryNode(void) const;
  BootSectorNode*       bootSectorNode(void) const;
  DFF::Node*            orphansNode(void) const;
  Unallocated*          unallocatedNode(void) const;
  MFTEntryManager&      mftManager(void); 
  const MFTEntryManager&      mftManager(void) const;
  int32_t 	        vread(int fd, void *buff, unsigned int size);
};

#endif
