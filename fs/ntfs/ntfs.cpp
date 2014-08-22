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

void    NTFS::declare(void) //XXX static loading
{
  Destruct::Destruct& destruct = Destruct::Destruct::instance();
  Destruct::DStruct* optStruct = Destruct::makeNewDCpp<NTFSOpt>("NTFSOpt");
  destruct.registerDStruct(optStruct);
  Destruct::DStruct* dntfsStruct = Destruct::makeNewDCpp<DNTFS>("DNTFS");
  destruct.registerDStruct(dntfsStruct);
  Destruct::DStruct* mftEntryManager = Destruct::makeNewDCpp<MFTEntryManager>("MFTEntryManager");
  destruct.registerDStruct(mftEntryManager);
}

/**
 *  NTFS 
 */
NTFS::NTFS() : mfso("NTFS"), __opt(NULL), __bootSectorNode(NULL), __mftManager(NULL), __rootDirectoryNode(new Node("NTFS")), __orphansNode(new Node("orphans")), __unallocatedNode(NULL)
{
 //XXX XXX must register DNTFS
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
  this->registerTree(this->opt()->fsNode(), this->rootDirectoryNode());
  this->__mftManager->linkOrphanEntries();
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
 
  DNTFS* dntfs = static_cast<DNTFS*>(value.get<Destruct::DObject*>());

  this->__opt = static_cast<NTFSOpt*>(static_cast<Destruct::DObject*>(dntfs->opt));
  this->__bootSectorNode = new BootSectorNode(this);
  if (this->__opt->validateBootSector())
    this->__bootSectorNode->validate();

  this->setStateInfo("Reading main MFT");

  this->__mftManager = static_cast<MFTEntryManager*>(static_cast<Destruct::DObject*>(dntfs->mftManager));
  this->__mftManager->init(this);
  this->__mftManager->initEntries();
  this->__mftManager->linkEntries(); 
  this->registerTree(this->opt()->fsNode(), this->rootDirectoryNode());
  this->__mftManager->linkOrphanEntries();
  this->registerTree(this->rootDirectoryNode(), this->orphansNode());
  this->__unallocatedNode = this->__mftManager->createUnallocated();
  if (this->__opt->recovery())
    this->__mftManager->linkUnallocated(this->__unallocatedNode);
  this->__mftManager->linkReparsePoint();
  //delete this->__mftManager; //Unallocated node use it 

  this->setStateInfo("Finished successfully");
  this->res["Result"] = Variant_p(new Variant(std::string("NTFS parsed successfully.")));


  return (true);
}

Destruct::DValue        NTFS::save(void) const //save(args) --> modules arg ? 
{
  std::cout << "NTFS save called" << std::endl;

  DNTFS* dntfs = static_cast<DNTFS*>(Destruct::makeNewDCpp<DNTFS>("DNTFS")->newObject());
  dntfs->opt = this->__opt;
  dntfs->mftManager = this->__mftManager;

  return (Destruct::RealValue<Destruct::DObject*>(dntfs));
}

/**
* DNTFS
* class to serialize for loading & saving
**/
DNTFS::DNTFS(Destruct::DStruct* dstruct, Destruct::DValue const& args) : DCppObject<DNTFS>(dstruct, args)
{
}

DNTFS::~DNTFS()
{
}
