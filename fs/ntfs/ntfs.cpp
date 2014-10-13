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

void    NTFS::declare(void) //XXX static loading
{
  Destruct::Destruct& destruct = Destruct::Destruct::instance();
  Destruct::DStruct* optStruct = Destruct::makeNewDCpp<NTFSOpt>("NTFSOpt");
  destruct.registerDStruct(optStruct);
   std::cout << "makeNewDCpp<DNtfs>(DNTFS)" << std::endl;
  Destruct::DStruct* dntfsStruct = Destruct::makeNewDCpp<DNTFS>("DNTFS");
   std::cout << "destruct.registerDStruct(dntfsStruct)" << std::endl;
  destruct.registerDStruct(dntfsStruct);
   std::cout << "makeNewDCpp<MFTEntryManager>" << std::endl;
  Destruct::DStruct* mftEntryManager = Destruct::makeNewDCpp<MFTEntryManager>("MFTEntryManager");
  destruct.registerDStruct(mftEntryManager);

  Destruct::DStruct* mftEntryInfo = new Destruct::DStruct(NULL, "MFTEntryInfo", Destruct::DSimpleObject::newObject);
  mftEntryInfo->addAttribute(Destruct::DAttribute(Destruct::DType::DUInt64Type, "id"));
  mftEntryInfo->addAttribute(Destruct::DAttribute(Destruct::DType::DObjectType, "childrenId"));
  mftEntryInfo->addAttribute(Destruct::DAttribute(Destruct::DType::DObjectType, "node"));
  mftEntryInfo->addAttribute(Destruct::DAttribute(Destruct::DType::DObjectType, "nodes"));
  mftEntryInfo->addAttribute(Destruct::DAttribute(Destruct::DType::DUInt64Type, "entryNode"));
  destruct.registerDStruct(mftEntryInfo);


  Destruct::DStruct* mftNode = new Destruct::DStruct(NULL, "MFTNode", Destruct::DSimpleObject::newObject);
  mftNode->addAttribute(Destruct::DAttribute(Destruct::DType::DUnicodeStringType, "name"));
  mftNode->addAttribute(Destruct::DAttribute(Destruct::DType::DUInt64Type, "mftEntryNode"));
  mftNode->addAttribute(Destruct::DAttribute(Destruct::DType::DUInt8Type, "isDirectory"));
  mftNode->addAttribute(Destruct::DAttribute(Destruct::DType::DUInt8Type, "isUsed"));
  mftNode->addAttribute(Destruct::DAttribute(Destruct::DType::DUInt8Type, "isCompressed"));
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
bool                    NTFS::load(Destruct::DValue value)
{
  ////XXX code me and it's done :) 
  std::cout << "NTFS load method called with " << value.asUnicodeString() << std::endl;

  Destruct::DObject* ntfsObject = value.get<Destruct::DObject*>();
  if (ntfsObject == Destruct::DNone)
  {
    std::cout << "can't reload NTFS object is DNone" << std::endl;
    return false;
  }

  DNTFS* dntfs = static_cast<DNTFS*>(ntfsObject);

  this->__opt = static_cast<NTFSOpt*>(static_cast<Destruct::DObject*>(dntfs->opt));
  this->__bootSectorNode = new BootSectorNode(this);
  if (this->__opt->validateBootSector())
    this->__bootSectorNode->validate();

  this->setStateInfo("Reading main MFT");
  this->__mftManager = static_cast<MFTEntryManager*>(static_cast<Destruct::DObject*>(dntfs->mftManager));

  this->__mftManager->init(this); //save & load
  this->__mftManager->initEntries(); //this-> dntfs->mftManager->entryList ? 
  this->__mftManager->linkEntries(); 
  this->__mftManager->linkOrphanEntries(); //save & load ?  for i in dntfs->mftManager->entryList getfname etc.. (a part si deja fait sous forme d abre donc zap aussi ce passage (for each node create node in the tree or simply relink the tree et rajouet la root mais node doit herited de dobject enfin MFTEntryNode : DObject comme ca le tree est directe ... peut etre le plus simple :) et chaque DMFTEntryNode garde les info qu il a besoin pour ce recree   

  this->registerTree(this->opt()->fsNode(), this->rootDirectoryNode());
  this->registerTree(this->rootDirectoryNode(), this->orphansNode());

  this->__unallocatedNode = this->__mftManager->createUnallocated();
  if (this->__opt->recovery())
    this->__mftManager->linkUnallocated(this->__unallocatedNode); //deja serializer

  this->__mftManager->linkReparsePoint();  //save & load reparse point (les sauvegarder/marquer creation de DVLink node ds le tree si on suavegtarde un tree ? comme ca pas a le refaire ?) 
  //delete this->__mftManager; //Unallocated node use it 

  this->setStateInfo("Finished successfully");
  this->res["Result"] = Variant_p(new Variant(std::string("NTFS parsed successfully.")));


  return (true);
}

Destruct::DValue        NTFS::save(void) const //save(args) --> modules arg ? 
{
  std::cout << "NTFS save called" << std::endl;

  try {

  DNTFS* dntfs = static_cast<DNTFS*>(Destruct::makeNewDCpp<DNTFS>("DNTFS")->newObject());
  dntfs->opt = this->__opt;
  if (this->__mftManager == NULL) //?
  {
    std::cout << "Can't save NTFS module applyied on node " << this->fsNode()->absolute() << std::endl;
    return (Destruct::RealValue<Destruct::DObject*>(Destruct::DNone));
  }
  dntfs->mftManager = this->__mftManager;


  Destruct::DObject* opt = dntfs->opt;
  opt->addRef();
  Destruct::DObject* mftManager = dntfs->mftManager;
  std::cout << "call MFTManager->saveEntries " << std::endl; 
  dntfs->setValue("entries", this->__mftManager->saveEntries());
 //XXX must delete it after c pas vraiment ca place car on le cree et on le garde ca sert a riuen :) 
  std::cout << "call MFTManager->saveEntries returned" << std::endl;
  std::cout << "entries refCount " << ((Destruct::DObject*)dntfs->entries)->instanceOf()->name() << " " << ((Destruct::DObject*)dntfs->entries)->refCount() << std::endl;

  mftManager->addRef();
  std::cout << "Returning dntfs " << std::endl;
  return (Destruct::RealValue<Destruct::DObject*>(dntfs));

  }
  catch (Destruct::DException const& exception)
  {
    std::cout << "NTFS::save exception " << exception.error() << std::endl;
    return (Destruct::RealValue<Destruct::DObject*>(Destruct::DNone));
  }
  //catch (std::bad_cast const& exception)
  //{
  //std::cout << "NTFS::bad cast " << exception.what() << std::endl;:
  //}
}

/**
* DNTFS
* class to serialize for loading & saving
**/
DNTFS::DNTFS(Destruct::DStruct* dstruct, Destruct::DValue const& args) : DCppObject<DNTFS>(dstruct, args)
{
  this->init();
}

DNTFS::~DNTFS()
{
}
