/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2014 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http://www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Frederic Baguelin <fba@digital-forensic.org>
 */


#include "hfshandlers.hpp"


HfspHandler::HfspHandler() : __allocationNode(NULL), __allocationFile(NULL), __fsobj(NULL)
{
}


HfspHandler::~HfspHandler()
{
}


void			HfspHandler::process(Node* origin, uint64_t offset, fso* fsobj) throw (std::string)
{
  this->setOrigin(origin, offset);
  this->setFsObject(fsobj);
  this->_createEtree();
  this->__createAllocation();
  this->_createCatalog();
}


void			HfspHandler::__createAllocation() throw (std::string)
{
  ForkData*		fork;
  VolumeHeader*		vheader;

  if ((vheader = dynamic_cast<VolumeHeader* >(this->_volumeInformation)) == NULL)
    throw std::string("Cannot get volume header on this HFS Volume");
  this->__allocationNode = new SpecialFile("$AllocationFile", this->_mountPoint, this->_fsobj);
  fork = new ForkData(6, this->_extentsTree);
  fork->process(vheader->allocationFile(), ForkData::Data);
  this->__allocationNode->setContext(fork, this->_origin);
  if (fork->initialForkSize() < fork->logicalSize())
    std::cout << "MISSING EXTENTS FOR ALLOCATION FILE !!!! " << std::endl;
  this->__allocationFile = new AllocationFile();
  this->__allocationFile->setFso(this->_fsobj);
  this->__allocationFile->setMountPoint(this->_mountPoint);
  this->__allocationFile->setExtentsTree(this->_extentsTree);
  this->__allocationFile->setOrigin(this->_origin);
  this->__allocationFile->process(this->__allocationNode, 0, this->_volumeInformation->totalBlocks());
}


uint64_t			HfspHandler::blockSize()
{
}


std::list<uint64_t>		HfspHandler::detetedEntries()
{
}


std::list<uint64_t>		HfspHandler::orphanEntries()
{
}


std::list<Node*>		HfspHandler::listFiles(uint64_t uid)
{
}


std::list<std::string>		HfspHandler::listNames(uint64_t uid)
{
}


Node*				HfspHandler::unallocatedSpace()
{
}


Node*				HfspHandler::freeSpace()
{
}


Node*				HfspHandler::slackSpace()
{
}


void				HfspHandler::report()
{
}