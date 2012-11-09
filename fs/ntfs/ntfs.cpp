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

NTFS::NTFS() : mfso("NTFS")
{
  this->__bootSectorNode = NULL;
  this->__rootDirectoryNode = new Node("NTFS");
}

NTFS::~NTFS()
{
  if (this->__bootSectorNode)
    delete this->__bootSectorNode;
  if (this->__rootDirectoryNode)
    delete this->__rootDirectoryNode;
}

void 		NTFS::start(Attributes args)
{
  this->__opt = new NTFSOpt(args);
  this->__bootSectorNode = new BootSectorNode(this);

  //boot sector node will not be created if invalid, all process will stop 
  if (this->__opt->validateBootSector())
    this->__bootSectorNode->validate();
 
  MFTNode* mftNode = new MFTNode(this, this->fsNode(), this->rootDirectoryNode(),  this->__bootSectorNode->MFTLogicalClusterNumber() * this->__bootSectorNode->clusterSize());
 

//bourin mode en faite on va lire les 7 premier car ils sont fix et apres utiliser l index pour reconstruire le tree correctemnt
//si non on read toute les mft comme un porcas et on fout l index ds un vector<>
//ca permetra d y acceder directement mais ca sera lour car on va les avir tous en ram
// on pourais  y acceder plus facilement en faisant mftNode->record(numero de l entry)
//le prob c que pour l instant on les lis relative a un offset number ce ki a rien a voir :) 
//donc faut voir le mieux mais apparement ca ce lis tjrs avec un numerod index ds la mft
//

  uint64_t i = 0;
  while (i * 1024 < mftNode->size())
  {
     new MFTNode(this, mftNode, this->rootDirectoryNode(), i * 1024);
     i+=1;
  }
//  MFTEntryNode* MFTEntryMirrorNode
// if MFTEntryNode != MFTEntryMirrorNode
  this->registerTree(this->opt()->fsNode(), this->rootDirectoryNode());

  this->setStateInfo("finished successfully");
  this->res["Result"] = Variant_p(new Variant(std::string("NTFS parsed successfully.")));
}

NTFSOpt*	NTFS::opt(void)
{
  return (this->__opt);
}

Node*		NTFS::fsNode(void)
{
  return (this->__opt->fsNode());
}

void 		NTFS::setStateInfo(const std::string info)
{
  this->stateinfo = info;
}

Node*		NTFS::rootDirectoryNode(void)
{
  return (this->__rootDirectoryNode);
}

BootSectorNode*	NTFS::bootSectorNode(void)
{
  return (this->__bootSectorNode);
}
