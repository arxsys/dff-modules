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
class DataNode;
class MFTEntryManager;
class Unallocated;

using namespace Destruct;

class DNTFS : public DCppObject<DNTFS>
{
public:
  DNTFS(DStruct* dstruct, DValue const& args);
  ~DNTFS();

  RealValue<DObject*>       opt, mftManager, entries;

  static size_t ownAttributeCount()
  {
    return (3);
  }

  static DAttribute* ownAttributeBegin()
  {
    static DAttribute  attributes[] = 
    {
      // DInt32Type "version" save version load & check for an other version (return false / throw)
      DAttribute(DType::DObjectType, "opt"),
      DAttribute(DType::DObjectType, "mftManager"),
      DAttribute(DType::DObjectType, "entries"),
    };
    return (attributes);
  }

  static DPointer<DNTFS>* memberBegin()
  {
    static DPointer<DNTFS> memberPointer[] = 
    {
      DPointer<DNTFS>(&DNTFS::opt),
      DPointer<DNTFS>(&DNTFS::mftManager),
      DPointer<DNTFS>(&DNTFS::entries),
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
};

class VoidNode : public DCppObject<VoidNode>
{
public:
  VoidNode(DStruct* dstruct, DValue const& args) : DCppObject<VoidNode>(dstruct, args)
  {
    //this->children = Destruct::Destruct::instance().generate("DVectorObject");  
  }
  ~VoidNode() {};

  RealValue<DObject*>       children;
  RealValue<DUnicodeString> name;

  static DObject*      save(Node* node)
  {
    DObject* voidNode = Destruct::Destruct::instance().generate("VoidNode");
    voidNode->setValue("name", RealValue<DUnicodeString>(node->name()));
    return voidNode;
  };     

  static Node*      load(DValue const& args)
  {
    DObject* dnode = args.get<DObject*>();
    std::string name = dnode->getValue("name").get<DUnicodeString>();
    return new Node(name);
  }

  static size_t ownAttributeCount()
  {
    return (2);
  }

  static DAttribute* ownAttributeBegin()
  {
    static DAttribute  attributes[] = 
    {
      DAttribute(DType::DUnicodeStringType, "name"),
      DAttribute(DType::DObjectType, "children"),
    };
    return (attributes);
  }

  static DPointer<VoidNode>* memberBegin()
  {
    static DPointer<VoidNode> memberPointer[] = 
    {
      DPointer<VoidNode>(&VoidNode::name),
      DPointer<VoidNode>(&VoidNode::children),
    };
    return (memberPointer);
  }

  static DAttribute* ownAttributeEnd()
  {
    return (ownAttributeBegin() + ownAttributeCount());
  }

  static DPointer<VoidNode>*  memberEnd()
  {
    return (memberBegin() + ownAttributeCount());
  }

};

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
  bool                  load(DValue value);
  DValue      save(void) const;
  DValue      saveTree(Node* node) const;
  Node*       loadTree(DValue const& args); 

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

#endif
