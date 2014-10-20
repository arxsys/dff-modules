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
#include "ntfs.hpp"
#include "ntfsopt.hpp"
#include "bootsector.hpp"
#include "mftentrynode.hpp"
#include "mftnode.hpp"
#include "mftattributecontent.hpp"
#include "mftattribute.hpp"
#include "mftmanager.hpp"
#include "attributes/data.hpp"

#include "protocol/dcppobject.hpp"
#include "dsimpleobject.hpp"

#include "time.h"

using namespace Destruct;

void    NTFS::declare(void) //XXX static loading
{
  Destruct::Destruct& destruct = Destruct::Destruct::instance();
  DStruct* optStruct = makeNewDCpp<NTFSOpt>("NTFSOpt");
  destruct.registerDStruct(optStruct);
  DStruct* dntfsStruct = makeNewDCpp<DNTFS>("DNTFS");
  destruct.registerDStruct(dntfsStruct);
  DStruct* mftEntryManager = makeNewDCpp<MFTEntryManager>("MFTEntryManager");
  destruct.registerDStruct(mftEntryManager);

  DStruct* mftEntryInfo = new DStruct(NULL, "MFTEntryInfo", DSimpleObject::newObject);
  mftEntryInfo->addAttribute(DAttribute(DType::DUInt64Type, "id"));
  mftEntryInfo->addAttribute(DAttribute(DType::DObjectType, "childrenId"));
  mftEntryInfo->addAttribute(DAttribute(DType::DObjectType, "node"));
  mftEntryInfo->addAttribute(DAttribute(DType::DObjectType, "nodes"));
  mftEntryInfo->addAttribute(DAttribute(DType::DUInt64Type, "entryNode"));
  destruct.registerDStruct(mftEntryInfo);

  DStruct* mappingAttributes = new DStruct(NULL, "MappingAttributes", DSimpleObject::newObject);
  mappingAttributes->addAttribute(DAttribute(DType::DUInt16Type, "offset"));
  mappingAttributes->addAttribute(DAttribute(DType::DUInt64Type, "mftEntryNode"));
  destruct.registerDStruct(mappingAttributes);


  DStruct* mftNode = new DStruct(NULL, "MFTNode", DSimpleObject::newObject);
  mftNode->addAttribute(DAttribute(DType::DUnicodeStringType, "name"));
  mftNode->addAttribute(DAttribute(DType::DUInt64Type, "mftEntryNode"));
  mftNode->addAttribute(DAttribute(DType::DUInt8Type, "isDirectory"));
  mftNode->addAttribute(DAttribute(DType::DUInt8Type, "isUsed"));
  mftNode->addAttribute(DAttribute(DType::DUInt8Type, "isCompressed"));
  mftNode->addAttribute(DAttribute(DType::DUInt64Type, "size"));
  mftNode->addAttribute(DAttribute(DType::DObjectType, "mappingAttributes"));
  destruct.registerDStruct(mftNode);
}

/**
 *  NTFS 
 */
NTFS::NTFS() : mfso("NTFS"), __opt(NULL), __bootSectorNode(NULL), __mftManager(NULL), __rootDirectoryNode(new Node("NTFS")), __orphansNode(new Node("orphans")), __unallocatedNode(NULL)
{
}

NTFS::~NTFS()
{
  if (this->__bootSectorNode)
    delete this->__bootSectorNode;
  if (this->__rootDirectoryNode)
    delete this->__rootDirectoryNode;
  if (this->__mftManager)
    delete this->__mftManager;
}

void    NTFS::start(Attributes args)
{
  Destruct::Destruct& destruct = Destruct::Destruct::instance();
  this->__opt = new NTFSOpt(args, destruct.find("NTFSOpt"));
  this->__bootSectorNode = new BootSectorNode(this);
  if (this->__opt->validateBootSector())
    this->__bootSectorNode->validate();

  /* 
   * GET MFT NODE 
   */ 
  this->setStateInfo("Reading main MFT");
  this->__mftManager = new MFTEntryManager(destruct.find("MFTEntryManager"));
  this->__mftManager->init(this);
  this->__mftManager->initEntries();
  this->__mftManager->linkEntries(); 
  this->__mftManager->linkOrphanEntries();
  this->registerTree(this->opt()->fsNode(), this->rootDirectoryNode()); //linkOprhanEntries do initEntries job actually
  this->registerTree(this->rootDirectoryNode(), this->orphansNode());
  this->__unallocatedNode = this->__mftManager->createUnallocated();
  if (this->__opt->recovery())
    this->__mftManager->searchUnallocated(this->__unallocatedNode);
  this->__mftManager->linkReparsePoint();
  //delete this->__mftManager; //Unallocated node use it 

  this->setStateInfo("Finished successfully");
  this->res["Result"] = Variant_p(new Variant(std::string("NTFS parsed successfully.")));
}

NTFSOpt*	NTFS::opt(void) const
{
  return (this->__opt);
}

MFTEntryManager* NTFS::mftManager(void) const
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
 
  MFTNode* mftNode = dynamic_cast<MFTNode* >(fi->node);
  if (mftNode == NULL)
    return (mfso::vread(fd, buff, size));

  if (fi->offset > mftNode->size())
    return (0);

  try 
  {
    if (!mftNode->isCompressed())
      return (mfso::vread(fd, buff, size));
    return (mftNode->readCompressed(buff, size, &fi->offset));
  }
  catch (const std::string& error)
  {
    std::string finalError = "NTFS::vread on " + mftNode->absolute() + " error: " + error;
    throw vfsError(finalError);
  }
}

/** Loading and saving method **/
bool                    NTFS::load(DValue value)
{
  ////XXX code me and it's done :) 
  std::cout << "NTFS load method called with " << value.asUnicodeString() << std::endl;

  DObject* ntfsObject = value.get<DObject*>();
  std::cout << "DNTFS ntfsObject refcount  " << ntfsObject->refCount() << std::endl; 
  if (ntfsObject == DNone)
  {
    std::cout << "can't reload NTFS object is DNone" << std::endl;
    return false;
  }

  DNTFS* dntfs = static_cast<DNTFS*>(ntfsObject);


  this->__opt = static_cast<NTFSOpt*>(static_cast<DObject*>(dntfs->opt));
  //this->__opt->addRef(); ?
  this->__bootSectorNode = new BootSectorNode(this);
  if (this->__opt->validateBootSector())
    this->__bootSectorNode->validate();

  this->setStateInfo("Reading main MFT");
  this->__mftManager = static_cast<MFTEntryManager*>(static_cast<DObject*>(dntfs->mftManager));
 //this->__mftManager-->addRef() ?

  this->__mftManager->init(this); //save & load

  time_t current;
  time_t after;

  std::cout << "loadEntries" << std::endl;
  time(&current);

  this->__mftManager->loadEntries(dntfs->entries, NULL);
  time(&after);
  std::cout << "loadEntries take: " << difftime(after, current) << std::endl;

  std::cout << "linkEntries" << std::endl; //serialize as a tree and serialize reparse at same time ?
  time(&current);
  this->__mftManager->linkEntries(); 
  time(&after);
  std::cout << "linkEntries take " << difftime(after, current) << std::endl;


  std::cout << "linkOrphanEntries" << std::endl;
  time(&current);
  this->__mftManager->linkOrphanEntries(); //save & load ?  for i in dntfs->mftManager->entryList getfname etc.. (a part si deja fait sous forme d abre donc zap aussi ce passage (for each node create node in the tree or simply relink the tree et rajouet la root mais node doit herited de dobject enfin MFTEntryNode : DObject comme ca le tree est directe ... peut etre le plus simple :) et chaque DMFTEntryNode garde les info qu il a besoin pour ce recree  
  time(&after); 
  std::cout << "linkOprhanEtries take " << difftime(after, current) << std::endl;

  this->registerTree(this->opt()->fsNode(), this->rootDirectoryNode());
  this->registerTree(this->rootDirectoryNode(), this->orphansNode());
  //
  std::cout << "createUnallocated" << std::endl; //OK ? 
  time(&current);
  this->__unallocatedNode = this->__mftManager->createUnallocated();
  if (this->__opt->recovery())
    this->__mftManager->linkUnallocated(this->__unallocatedNode); //deja serializer
  time(&after); 
  std::cout << "createUnallocated take " << difftime(after, current) << std::endl;
  
  std::cout << "linkReparsePoint " << std::endl; //XXX serialize ?
  time(&current);
  this->__mftManager->linkReparsePoint();
  time(&after); 
  std::cout << "linkReparsePoint take " << difftime(after, current) << std::endl;
  //delete this->__mftManager; //Unallocated node use it 
 
  dntfs->destroy();//??
  std::cout << "Ref dntfs " << dntfs->refCount() << " ref opt " << this->__opt->refCount() << " ref mftManager " << this->__mftManager->refCount() << std::endl;
 
  this->setStateInfo("Reloading finished successfully");
  this->res["Result"] = Variant_p(new Variant(std::string("NTFS parsed successfully.")));

  return (true);
}

DValue        NTFS::save(void) const //save(args) --> modules arg ? 
{
  std::cout << "NTFS save called" << std::endl;

  try {

  DNTFS* dntfs = static_cast<DNTFS*>(makeNewDCpp<DNTFS>("DNTFS")->newObject());
  dntfs->opt = this->__opt;
  if (this->__mftManager == NULL) //?
  {
    std::cout << "Can't save NTFS module applyied on node " << this->fsNode()->absolute() << std::endl;
    return (RealValue<DObject*>(DNone));
  }
  dntfs->mftManager = this->__mftManager;


  DObject* opt = dntfs->opt;
  opt->addRef();
  DObject* mftManager = dntfs->mftManager;
  std::cout << "call MFTManager->saveEntries " << std::endl; 
  dntfs->setValue("entries", this->__mftManager->saveEntries());
 //XXX must delete it after c pas vraiment ca place car on le cree et on le garde ca sert a riuen :) 
  std::cout << "call MFTManager->saveEntries returned" << std::endl;
  std::cout << "entries refCount " << ((DObject*)dntfs->entries)->instanceOf()->name() << " " << ((DObject*)dntfs->entries)->refCount() << std::endl;

  mftManager->addRef();
  std::cout << "Returning dntfs " << std::endl;
  return (RealValue<DObject*>(dntfs));

  }
  catch (DException const& exception)
  {
    std::cout << "NTFS::save exception " << exception.error() << std::endl;
    return (RealValue<DObject*>(DNone));
  }
  catch (std::bad_cast const& exception)
  {
    std::cout << "NTFS::bad cast " << exception.what() << std::endl;
    return (RealValue<DObject*>(DNone));
  }
}

/**
* DNTFS
* class to serialize for loading & saving
**/
DNTFS::DNTFS(DStruct* dstruct, DValue const& args) : DCppObject<DNTFS>(dstruct, args)
{
  this->init();
}

DNTFS::~DNTFS()
{
}
