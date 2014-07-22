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

#include "catalogtree.hpp"
#include <unicode/unistr.h>


CatalogTreeNode::CatalogTreeNode()
{
  
}


CatalogTreeNode::~CatalogTreeNode()
{
  
}


void	CatalogTreeNode::process(Node* origin, uint64_t uid, uint16_t size) throw (std::string)
{
  HNode::process(origin, uid, size);
}

KeyedRecords	CatalogTreeNode::records()
{
  std::string	error;
  KeyedRecord*	record;
  KeyedRecords	records;
  int		i;
  

  if (this->isLeafNode() && (this->numberOfRecords() > 0))
    {
      for (i = this->numberOfRecords(); i > 0; i--)
	{
	  record = this->__createCatalogKey(bswap16(this->_roffsets[i]), bswap16(this->_roffsets[i-1]));
	  records.push_back(record);
	}
    }
  else
    records = HNode::records();
  return records;  
}


KeyedRecord*	CatalogTreeNode::__createCatalogKey(uint16_t start, uint16_t end)
{
  CatalogKey*	record;
  uint64_t	offset;
  uint16_t	size;

  offset = this->offset() + start;
  size = 0;
  if (start < end)
    size = end - start;
  record = new CatalogKey();
  record->setOrigin(this->_origin);
  record->setOffset(offset);
  record->setSize(size);
  return record;
}


//
// Catalog HTree implementation
//
CatalogTree::CatalogTree()
{
  this->__catalog = NULL;
  this->__origin = NULL;
  this->__mountpoint = NULL;
  this->__fsobj = NULL;
  this->__etree = NULL;
  this->__allocatedBlocks = NULL;
  this->__fileCount = 0;
  this->__folderCount = 0;
  this->__fileThreadCount = 0;
  this->__folderThreadCount = 0;
}


CatalogTree::~CatalogTree()
{
}


void	CatalogTree::setFso(fso* fsobj)
{
  this->__fsobj = fsobj;
}


void	CatalogTree::setOrigin(Node* origin) throw (std::string)
{
  if (origin == NULL)
    throw std::string("Provided origin does not exist");
  this->__origin = origin;
}


void	CatalogTree::setMountPoint(Node* mountpoint) throw (std::string)
{
  if (mountpoint == NULL)
    throw std::string("Provided mount point does not exist");
  this->__mountpoint = mountpoint;
}


void	CatalogTree::setExtentsTree(ExtentsTree* etree) throw (std::string)
{
  if (etree == NULL)
    throw std::string("Cannot create Catalog tree because provided Extent tree does not exist");
  this->__etree = etree;
}


void			CatalogTree::process(Node* catalog, uint64_t offset) throw (std::string)
{
  uint64_t				idx;
  CatalogTreeNode*			cnode;
  HfsNodesMapping::iterator		mit;
  std::vector<HfsNode*>::iterator	it;
  std::stringstream			sstr;

  HTree::process(catalog, offset);
  if ((cnode = new CatalogTreeNode()) == NULL)
    throw std::string("Cannot create catalog node");
  if ((this->__allocatedBlocks = new TwoThreeTree()) == NULL)
    throw std::string("Cannot create allocated blocks status");
  sstr << "Proceesing catalog tree";
  for (idx = 0; idx < this->totalNodes(); idx++)
    {
      try
	{
	  cnode->process(catalog, idx, this->nodeSize());
	  if (cnode->isLeafNode())
	    this->__makeNodes(catalog, cnode);
	}
      catch (std::string err)
	{
	  std::cout << "Error while making node" << err << std::endl;
	}
      // sstr << "Processing nodes in catalog tree: " << idx << " / " << this->totalNodes();
      // this->__fsobj->stateinfo = sstr.str();
      // sstr.str("");
    }
  sstr << "Processing nodes in catalog tree: " << idx << " / " << this->totalNodes();
  this->__fsobj->stateinfo = sstr.str();
  sstr.str("");
  if ((mit = this->__nodes.find(1)) != this->__nodes.end())
    {
      for (it = mit->second.begin(); it != mit->second.end(); it++)
	{
	  this->__mountpoint->addChild(*it);
	  if ((*it)->hfsType() == HfsNode::Folder)
	    this->__linkNodes((*it), (*it)->cnid());
	}
      mit->second.clear();
    }
  // XXX implement dedicated method to manage potential orphans
  for (mit = this->__nodes.begin(); mit != this->__nodes.end(); mit++)
    if (mit->second.size() > 0)
      std::cout << "orphan entry found: " << mit->first << std::endl;
}


void				CatalogTree::__makeNodes(Node* catalog, CatalogTreeNode* cnode)
{
  KeyedRecords			records;
  KeyedRecords::iterator	rit;
  CatalogKey*			ckey;
  HfsNode*			node;

  records = cnode->records();
  for (rit = records.begin(); rit != records.end(); rit++)
    {
      (*rit)->process();
      ckey = dynamic_cast<CatalogKey*>(*rit);
      node = NULL;
      if (ckey->type() == CatalogKey::FileRecord)
	{
	  this->__fileCount++;
	  node = new HfsFile(ckey->parentId(), ckey->name(), this->__fsobj);
	  node->setFile();
	}
      else if (ckey->type() == CatalogKey::FolderRecord)
	{
	  this->__folderCount++;
	  node = new HfsFolder(ckey->parentId(), ckey->name(), this->__fsobj);
	  node->setDir();
	}
      if (node != NULL)
	{
	  node->process(this->__origin, catalog, ckey->offset()+ckey->dataOffset(), this->__etree);
	  this->__nodes[node->parentId()].push_back(node);
	}
      delete ckey;
    }
  records.clear();
}


void	CatalogTree::__linkNodes(HfsNode* parent, uint32_t parentId)
{
  std::map<uint32_t, std::vector<HfsNode*> >::iterator	mit;
  std::vector<HfsNode*>::iterator			it;

  if ((mit = this->__nodes.find(parentId)) != this->__nodes.end())
    {
      for (it = mit->second.begin(); it != mit->second.end(); it++)
	{
	  parent->addChild(*it);
	  if ((*it)->hfsType() == HfsNode::Folder)
	    this->__linkNodes((*it), (*it)->cnid());
	  // else
	  //   this->__registerAllocatedBlocks(*it);
	}
      mit->second.clear();
    }
}


void	CatalogTree::__registerAllocatedBlocks(HfsNode* node)
{
  HfsFile*		file;
  ForkData*		fork;
  ExtentsList           extents;
  ExtentsList::iterator it;
  uint64_t		bcount;
  uint64_t		sblock;

  
  if (node->hfsType() == HfsNode::File)
    {
      file = dynamic_cast<HfsFile*>(node);
      fork = file->dataFork();
      extents = fork->extents();
      for (it = extents.begin(); it != extents.end(); it++)
	{
	  sblock = (*it)->startBlock();
	  this->__allocatedBlocks->insert(sblock);
	  for (bcount = 0; bcount != (*it)->blockCount(); ++bcount)
	    this->__allocatedBlocks->insert(sblock++);
	}
      delete fork;
    }
}
