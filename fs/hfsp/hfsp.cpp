/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
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

#include "hfsp.hpp"
#include "allocation.hpp"
#include "catalog/catalogtree.hpp"

Hfsp::Hfsp() : mfso("hfsp"), __parent(NULL), __root(NULL)
{
}


Hfsp::~Hfsp()
{
}


void		Hfsp::start(std::map<std::string, Variant_p > args)
{
  try
    {
      this->__setContext(args);
      this->__process();
    }
  catch(std::string e)
    {
      throw (e);
    }
  catch(vfsError e)
    {
      throw (e);
    }
  catch(envError e)
    {
      throw (e);
    }
  return ;
}


void		Hfsp::__process() throw (std::string)
{
  VolumeHeader*		volume;
  ExtentsTree*		etree;
  AllocationFile*	afile;
  
  
  volume = NULL;
  etree = NULL;
  afile = NULL;
  try
    {
      volume = new VolumeHeader();
      volume->process(this->__parent, this);
      this->res["Volume header"] = new Variant(volume->_attributes());
      if (volume->isHfspVolume())
  	this->__root = new HfsRootNode("HFSP", 0, NULL, this);
      else if (volume->isHfsxVolume())
  	this->__root = new HfsRootNode("HFSX", 0, NULL, this);
      else
  	this->__root = new HfsRootNode("HFS?", 0, NULL, this);
      this->__root->setVolumeHeader(volume);
      etree = this->__createEtree(volume);
      afile = this->__createAllocation(volume, etree);
      this->__createCatalog(volume, etree);
      this->registerTree(this->__parent, this->__root);
      this->stateinfo = std::string("Successfully mounted");
    }
  catch(...)
    {
      if (this->__root != NULL)
	delete this->__root;
      if (volume != NULL)
	delete volume;
      if (etree != NULL)
	delete etree;
      if (afile != NULL)
	delete afile;
      throw(std::string("HFS module: error while processing"));
      this->stateinfo = std::string("Error while mounting");
    }
  return;
}


ExtentsTree*	Hfsp::__createEtree(VolumeHeader* volume) throw (std::string)
{
  SpecialFile*	enode;
  ForkData*	fork;
  ExtentsTree*	etree;

  enode = new SpecialFile("$ExtentsFile", this->__root, this);
  fork = new ForkData(3, volume->blockSize());
  fork->process(volume->extentsFile(), ForkData::Data);
  enode->setContext(fork, this->__parent);
  etree = new ExtentsTree();
  etree->setBlockSize(volume->blockSize());
  etree->process(enode, 0);
  return etree;
}


void		Hfsp::__createCatalog(VolumeHeader* volume, ExtentsTree* etree) throw (std::string)
{
  SpecialFile*	enode;
  ForkData*	fork;
  CatalogTree*	ctree;
  
  enode = new SpecialFile("$CatalogFile", this->__root, this);
  fork = new ForkData(4, etree);
  fork->process(volume->catalogFile(), ForkData::Data);
  enode->setContext(fork, this->__parent);
  if (fork->initialForkSize() < fork->logicalSize())
    std::cout << "MISSING EXTENTS FOR CATALOG !!!! " << std::endl;
  ctree = new CatalogTree();
  ctree->setFso(this);
  ctree->setMountPoint(this->__root);
  ctree->setExtentsTree(etree);
  ctree->setOrigin(this->__parent);
  ctree->process(enode, 0);
}


AllocationFile*		Hfsp::__createAllocation(VolumeHeader* volume, ExtentsTree* etree) throw (std::string)
{
  SpecialFile*		enode;
  ForkData*		fork;
  AllocationFile*	alloc;

  enode = new SpecialFile("$AllocationFile", this->__root, this);
  fork = new ForkData(6, etree);
  fork->process(volume->allocationFile(), ForkData::Data);
  enode->setContext(fork, this->__parent);
  if (fork->initialForkSize() < fork->logicalSize())
    std::cout << "MISSING EXTENTS FOR ALLOCATION FILE !!!! " << std::endl;
  alloc = new AllocationFile();
  alloc->setFso(this);
  alloc->setMountPoint(this->__root);
  alloc->setExtentsTree(etree);
  alloc->setOrigin(this->__parent);
  alloc->process(enode, 0, volume->totalBlocks());
  return alloc;
}


void		Hfsp::__setContext(std::map<std::string, Variant_p > args) throw (std::string)
{
  std::map<std::string, Variant_p >::iterator	it;

  if ((it = args.find("file")) != args.end())
    this->__parent = it->second->value<Node*>();
  else
    throw(std::string("Hfsp module: no file provided"));
  return;
}


void		HfsRootNode::setVolumeHeader(VolumeHeader* vheader)
{
  this->__vheader = vheader;
}

Attributes	HfsRootNode::_attributes()
{
  return this->__vheader->_attributes();
}
