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
#include <iostream>

#include "ntfs.hpp"
#include "ntfsopt.hpp"
#include "bootsector.hpp"
#include "mftentrynode.hpp"
#include "mftnode.hpp"

NTFS::NTFS() : mfso("NTFS"), __opt(NULL), __rootDirectoryNode(new Node("NTFS")), __bootSectorNode(NULL)
{
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

  if (this->__opt->validateBootSector())
    this->__bootSectorNode->validate();

  this->setStateInfo("Reading main MFT");
  MFTNode* mftNode = new MFTNode(this, this->fsNode(), this->rootDirectoryNode(),  this->__bootSectorNode->MFTLogicalClusterNumber() * this->__bootSectorNode->clusterSize());

  uint64_t i = 0;
  uint64_t nMFT = mftNode->size() / this->bootSectorNode()->MFTRecordSize();

  std::ostringstream nMFTStream;
  nMFTStream  << std::string("Found ") << nMFT <<  std::string(" MFT entry") << endl;
  this->setStateInfo(nMFTStream.str());

  while (i * this->bootSectorNode()->MFTRecordSize() < mftNode->size())
  {
    if (i % 1000 == 0)
    {
      std::ostringstream cMFTStream;
      cMFTStream << "Parsing " << i << "/" << nMFT;
      this->setStateInfo(cMFTStream.str());
    }
    try 
    {
      MFTNode* currentMFTNode = new MFTNode(this, mftNode, NULL, i * this->bootSectorNode()->MFTRecordSize());
      this->rootDirectoryNode()->addChild(currentMFTNode);
    }
    catch (std::string& error)
    {
      std::cout << "Can't create MFTNode" << i << " error: " << error << std::endl;
    }
    i += 1;
  }
  this->registerTree(this->opt()->fsNode(), this->rootDirectoryNode());

  this->setStateInfo("finished successfully");
  this->res["Result"] = Variant_p(new Variant(std::string("NTFS parsed successfully.")));
}

NTFSOpt*	NTFS::opt(void) const
{
  return (this->__opt);
}

Node*		NTFS::fsNode(void) const
{
  return (this->__opt->fsNode());
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
