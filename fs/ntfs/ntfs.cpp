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
#include "vlink.hpp"
#include "fdmanager.hpp"
#include "ntfs.hpp"
#include "ntfsopt.hpp"
#include "bootsector.hpp"
#include "mftentrynode.hpp"
#include "datanode.hpp"
#include "mftattributecontent.hpp"
#include "mftattribute.hpp"
#include "mftmanager.hpp"
#include "attributes/data.hpp"
#include "unallocated.hpp"

#include "protocol/dcppobject.hpp"
#include "dsimpleobject.hpp"

#include "time.h"

using namespace Destruct;

void    NTFS::declare(void)
{
  Destruct::DStructs& destruct(Destruct::DStructs::instance());
  DStruct* optStruct(makeNewDCpp<NTFSOpt>("NTFSOpt"));
  destruct.registerDStruct(optStruct);
  DStruct* dntfsStruct(makeNewDCpp<DNTFS>("DNTFS")); 
  destruct.registerDStruct(dntfsStruct);

  DStruct* mftEntryInfo(new DStruct(NULL, "MFTEntryInfo", DSimpleObject::newObject));
  mftEntryInfo->addAttribute(DAttribute(DType::DUInt64Type, "id"));
  mftEntryInfo->addAttribute(DAttribute(DType::DObjectType, "childrenId"));
  mftEntryInfo->addAttribute(DAttribute(DType::DObjectType, "node"));
  mftEntryInfo->addAttribute(DAttribute(DType::DObjectType, "nodes"));
  mftEntryInfo->addAttribute(DAttribute(DType::DObjectType, "entryNode"));
  destruct.registerDStruct(mftEntryInfo);

  DStruct* mappingAttributes(new DStruct(NULL, "MappingAttributes", DSimpleObject::newObject));
  mappingAttributes->addAttribute(DAttribute(DType::DUInt16Type, "offset"));
  mappingAttributes->addAttribute(DAttribute(DType::DObjectType, "mftEntryNode"));
  destruct.registerDStruct(mappingAttributes);

  DStruct* dataNode(new DStruct(NULL, "DataNode", DSimpleObject::newObject));
  dataNode->addAttribute(DAttribute(DType::DUnicodeStringType, "name"));
  dataNode->addAttribute(DAttribute(DType::DObjectType, "mftEntryNode"));
  dataNode->addAttribute(DAttribute(DType::DUInt8Type, "isCompressed"));
  dataNode->addAttribute(DAttribute(DType::DUInt64Type, "size"));
  dataNode->addAttribute(DAttribute(DType::DObjectType, "mappingAttributes"));
  dataNode->addAttribute(DAttribute(DType::DObjectType, "children"));
  destruct.registerDStruct(dataNode);

  DStruct* mftNode(new DStruct(NULL, "MFTNode", DSimpleObject::newObject));
  mftNode->addAttribute(DAttribute(DType::DUInt64Type, "offset"));
  destruct.registerDStruct(mftNode);

  DStruct* mftEntryNode(new DStruct(NULL, "MFTEntryNode", DSimpleObject::newObject));
  mftEntryNode->addAttribute(DAttribute(DType::DUInt64Type, "offset"));
  mftEntryNode->addAttribute(DAttribute(DType::DUInt64Type, "mftNodeOffset"));
  destruct.registerDStruct(mftEntryNode);

  DStruct* unallocated(new DStruct(NULL, "Unallocated", DSimpleObject::newObject));
  unallocated->addAttribute(DAttribute(DType::DUInt64Type, "size"));
  unallocated->addAttribute(DAttribute(DType::DObjectType, "ranges"));
  unallocated->addAttribute(DAttribute(DType::DObjectType, "children"));

  destruct.registerDStruct(unallocated);

  DStruct* range(new DStruct(NULL, "Range", DSimpleObject::newObject));
  range->addAttribute(DAttribute(DType::DUInt64Type, "start"));
  range->addAttribute(DAttribute(DType::DUInt64Type, "end"));
  destruct.registerDStruct(range);
}

/**
 *  NTFS 
 */
NTFS::NTFS() : mfso("NTFS"), __opt(NULL), __bootSectorNode(NULL), __rootDirectoryNode(new Node("NTFS", 0, NULL, this)), __orphansNode(new Node("orphans", 0, NULL, this)), __unallocatedNode(NULL)
{
  
}

NTFS::~NTFS()
{
  if (this->__bootSectorNode)
    delete this->__bootSectorNode;
  if (this->__rootDirectoryNode)
    delete this->__rootDirectoryNode;
}

void    NTFS::start(Attributes args)
{
  Destruct::DStructs& destruct(Destruct::DStructs::instance());
  this->__opt = new NTFSOpt(args, destruct.find("NTFSOpt"));
  this->__bootSectorNode = new BootSectorNode(this);
  if (this->__opt->validateBootSector())
    this->__bootSectorNode->validate();

  /* 
   * GET MFT NODE 
   */ 
  this->setStateInfo("Reading main MFT");
  this->__mftManager.init(this);
  this->__mftManager.initEntries();
  this->__mftManager.linkEntries(); 
  this->__mftManager.linkOrphanEntries();
  this->registerTree(this->opt()->fsNode(), this->rootDirectoryNode()); //linkOprhanEntries do initEntries job actually
  this->registerTree(this->rootDirectoryNode(), this->orphansNode());
  this->__unallocatedNode = this->__mftManager.createUnallocated();
  if (this->__opt->recovery())
    this->__mftManager.searchUnallocated(this->__unallocatedNode);
  this->__mftManager.linkReparsePoint();
  //delete this->__mftManager; //Unallocated node use it 

  this->setStateInfo("Finished successfully");
  this->res["Result"] = Variant_p(new Variant(std::string("NTFS parsed successfully.")));
}

NTFSOpt*	NTFS::opt(void) const
{
  return (this->__opt);
}

MFTEntryManager& NTFS::mftManager(void)
{
  return (this->__mftManager);
}

const MFTEntryManager& NTFS::mftManager(void) const
{
  return (this->__mftManager);
}

Node*		NTFS::fsNode(void) const
{
  return (this->__opt->fsNode());
}

Node*           NTFS::orphansNode(void) const
{
  return (this->__orphansNode);
}

void 		NTFS::setStateInfo(const std::string& info)
{
  this->stateinfo = std::string(info);
}

Node*		NTFS::rootDirectoryNode(void) const
{
  return (this->__rootDirectoryNode);
}

BootSectorNode*	NTFS::bootSectorNode(void) const
{
  return (this->__bootSectorNode);
}

Unallocated*    NTFS::unallocatedNode(void) const
{
  return (this->__unallocatedNode);
}

/**
 *  Redefine read to use both file mapping
 *  and special read method for compressed data
 */
int32_t  NTFS::vread(int fd, void *buff, unsigned int size)
{
  fdinfo* fi = NULL;
  try
  {
    fi = this->__fdmanager->get(fd);
  }
  catch (vfsError const& e)
  {
    return (0); 
  }
  catch (std::string const& e)
  {
    return (0);
  }
 
  DataNode* dataNode = dynamic_cast<DataNode* >(fi->node);
  if (dataNode == NULL)
    return (mfso::vread(fd, buff, size));

  if (fi->offset > dataNode->size())
    return (0);

  try 
  {
    if (!dataNode->isCompressed())
      return (mfso::vread(fd, buff, size));
    return (dataNode->readCompressed(buff, size, &fi->offset));
  }
  catch (const std::string& error)
  {
    std::string finalError = "NTFS::vread on " + dataNode->absolute() + " error: " + error;
    throw vfsError(finalError);
  }
}

/** 
 *  Loading and saving method 
 **/
bool                    NTFS::load(DValue value)
{
  DObject* ntfsObject = value.get<DObject*>();
  if (ntfsObject == DNone)
    return (false);

  DNTFS* dntfs = static_cast<DNTFS*>(ntfsObject);
  if (dntfs->getValue("version").get<DUInt8>() != NTFS_VERSION)
    return (false); //throw wrong version ? & reload  

  this->__opt = static_cast<NTFSOpt*>(static_cast<DObject*>(dntfs->opt));
  this->__bootSectorNode = new BootSectorNode(this);
  if (this->__opt->validateBootSector())
    this->__bootSectorNode->validate();

  this->__mftManager.init(this);  //reload mster mft node ? 
  Node* rootNode = this->loadTree(dntfs->entries);
  this->__rootDirectoryNode = rootNode;

  DObject* vlinks = dntfs->reparsePoints;
  DUInt64 size = vlinks->call("size").get<DUInt64>();

  this->registerTree(this->opt()->fsNode(), rootNode);
  this->registerTree(rootNode, this->bootSectorNode()); //register before else can't find vlink  by getnode 

  for (DUInt64 index = 0; index < size; ++index)
    VLink::load(vlinks->call("get", RealValue<DUInt64>(index)));


  //std::cout << "status at end      dntfs : " << dntfs->refCount() << std::endl
  //<< "                   dntfs->opt " << ((DObject*)dntfs->opt)->refCount() << std::endl
  //<< "                   dntfs->entries " << (((DObject*)dntfs->entries)->refCount()) << std::endl
  //<< "                   dntfs->reparsePoints " << ((DObject*)dntfs->reparsePoints)->refCount() << std::endl;

  //((DObject*)dntfs->entries)->destroy(); //pu utiliser
  //((DObject*)dntfs->reparsePoints)->destroy(); //pu utiliser
  ////dntfs->entries->opt(); //utiliser
  //((DObject*)dntfs->opt)->destroy();
  //dntfs->destroy();
  //dntfs->destroy();
  //dntfs->destroy();
  //dntfs->destroy(); //faire une copy est destroy i lest a 5 ref lui c spe
  //std::cout << "status at end      dntfs : " << dntfs->refCount() << std::endl
  //<< "                   dntfs->opt " << ((DObject*)dntfs->opt)->refCount() << std::endl
  //<< "                   dntfs->entries " << (((DObject*)dntfs->entries)->refCount()) << std::endl
  //<< "                   dntfs->reparsePoints " << ((DObject*)dntfs->reparsePoints)->refCount() << std::endl;
  //

  this->setStateInfo("Finished successfully");
  this->res["Result"] = Variant_p(new Variant(std::string("NTFS parsed successfully.")));

  return (true);
}

Node*         NTFS::loadTree(DValue const& value)
{
  Node*  node = NULL;
  DObject* dnode(value.get<DObject*>());

  if (dnode == DNone)
    return (NULL);

  std::string objectType = dnode->instanceOf()->name();
  if (objectType == "DataNode")
  {
    try 
    {
      node = DataNode::load(this, value); 
    }
    catch (...)
    {
      std::cout << "Can't load DataNode or MFTNode " << dnode->getValue("name").get<DUnicodeString>() << std::endl;
      node = VoidNode::load(this, value);
    }
  }
  else if (objectType == "Unallocated")
    node = Unallocated::load(this, value);
  else
    node = VoidNode::load(this, value); //must pass fso or will not be marked as ntfs anymore

  DObject* dchildren(dnode->getValue("children").get<DObject*>());
  if (dchildren != DNone)
  {
    DUInt64 size(dchildren->call("size").get<DUInt64>());
    for (DUInt64 current = 0; current < size; ++current)
    {
      DObject* dchild(dchildren->call("get", RealValue<DUInt64>(current)).get<DObject*>());
      Node* child(this->loadTree(RealValue<DObject*>(dchild)));
      if (child)
        node->addChild(child);
      dchild->destroy();
    }
  }

  dchildren->destroy();
  dnode->destroy();
  return (node);
}

DValue        NTFS::save(void) const
{
  DNTFS* dntfs(static_cast<DNTFS*>(makeNewDCpp<DNTFS>("DNTFS")->newObject()));
  dntfs->opt = this->__opt;

  if (this->__bootSectorNode == NULL)
    return (RealValue<DObject*>(DNone));

  dntfs->entries = saveTree(this->rootDirectoryNode());

  dntfs->reparsePoints = Destruct::DStructs::instance().generate("DVectorObject");
  DObject* reparsePoints = dntfs->reparsePoints;
  const std::vector<VLink*>& vlinks = this->__mftManager.vlinks();
  std::vector<VLink*>::const_iterator vlink = vlinks.begin();
  for (; vlink != vlinks.end(); ++vlink)
     reparsePoints->call("push", (*vlink)->save());

  //std::cout << "save ntfs " << this->rootDirectoryNode()->absolute() << std::endl;
  return (RealValue<DObject*>(dntfs));
}

DValue        NTFS::saveTree(Node* node) const
{
  if (!node || node->fsobj() != this || node == this->__bootSectorNode)
    return RealValue<DObject*>(DNone);

  if (dynamic_cast<VLink*>(node)) //don't save vlink yet (& don't follow it, we will use the reparse point func later) or use it now but don't use reparse point func ... XXX
    return RealValue<DObject*>(DNone);

  DValue nodeValue = node->save();
  DObject* dnode = nodeValue.get<DObject*>();

  try
  {
    DObject* dchildren(dnode->getValue("children").get<DObject*>());
    if (dchildren == DNone) // ?
    {
      dchildren = Destruct::DStructs::instance().generate("DVectorObject");
      dnode->setValue("children", RealValue<DObject*>(dchildren));
    }
    std::vector<Node*> children(node->children());
    std::vector<Node*>::const_iterator child = children.begin();
    for (; child != children.end(); ++child)
      dchildren->call("push", this->saveTree(*child));
  }
  catch (DException const& exception) //NTFS generate DVLink who didn't have children attribute
  { 
    std::cout << "Can't save children of node " << node->absolute() << std::endl; //XXX Error with reparse point
  }

  dnode->destroy();
  return (nodeValue);
}

/**
* DNTFS
* class to serialize for loading & saving
**/
DNTFS::DNTFS(DStruct* dstruct, DValue const& args) : DCppObject<DNTFS>(dstruct, args), __version(NTFS_VERSION)
{
  this->init();
}

DNTFS::~DNTFS()
{
}
