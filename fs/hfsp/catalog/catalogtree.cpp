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
#include "hfsrecords.hpp"
#include "hfsprecords.hpp"


CatalogTreeNode::CatalogTreeNode(uint8_t version) : __version(version)
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
	  try
	    {
	      record = this->__createCatalogKey(bswap16(this->_roffsets[i]), bswap16(this->_roffsets[i-1]));
	      if (record != NULL)
		records.push_back(record);
	      //record->hexdump(1, 1);
	    }
	  catch (std::string err)
	    {
	      //std::cout << "[ERROR] " << err << std::endl;	      
	      //record->hexdump(1, 1);
	    }
	  //std::cout << "Loop" << std::endl;
	}
    }
  else
    records = HNode::records();
  return records;  
}


KeyedRecord*	CatalogTreeNode::__createCatalogKey(uint16_t start, uint16_t end)
{
  CatalogEntry*	record;
  uint64_t	offset;
  uint16_t	size;

  record = NULL;
  offset = this->offset() + start;
  size = 0;
  if (start < end)
    size = end - start;
  if (this->__version == 0)
    record = new HfsCatalogEntry();
  else
    record = new HfspCatalogEntry();
  if (record != NULL)
    {
      record->setSizeofKeyLengthField(this->_klenfield);
      // using the buffer version in order to not read the same buffer twice
      record->process(this->_buffer+start, size);
      record->setContext(this->_origin, offset, size);
    }
  return record;
}


//
// Catalog HTree implementation
//
CatalogTree::CatalogTree(uint8_t version)
{
  //this->__catalog = NULL;
  //this->__fsobj = NULL;
  //this->__etree = NULL;
  this->__allocatedBlocks = NULL;
  this->__version = version;
  this->__fileCount = 0;
  this->__folderCount = 0;
  this->__fileThreadCount = 0;
  this->__folderThreadCount = 0;
  this->__indexRecords = 0;
  this->__effectiveLeafRecords = 0;
  this->__percent = 0;
}


CatalogTree::~CatalogTree()
{
}


void	CatalogTree::setHandler(HfsFileSystemHandler* handler) throw (std::string)
{
  if (handler == NULL)
    throw std::string("Cannot create Catalog tree because provided handler does not exist");
  this->__handler = handler;
}


void			CatalogTree::process(Node* catalog, uint64_t offset) throw (std::string)
{
  uint64_t				idx;
  CatalogTreeNode*			cnode;
  HfsNodesMapping::iterator		mit;
  std::vector<HfsNode*>::iterator	it;
  std::stringstream			sstr;

  HTree::process(catalog, offset);
  if ((cnode = new CatalogTreeNode(this->__version)) == NULL)
    throw std::string("Cannot create catalog node");
  cnode->setSizeofKeyLengthField(this->sizeOfKey());
  if ((this->__allocatedBlocks = new TwoThreeTree()) == NULL)
    throw std::string("Cannot create allocated blocks status");
  sstr << "Proceesing catalog tree";
  this->__percent = 0;
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
	  //std::cout << "Error while making node" << err << std::endl;
	}
      this->__progress(idx);
    }
  this->__progress(idx);
  if ((mit = this->__nodes.find(1)) != this->__nodes.end())
    {
      for (it = mit->second.begin(); it != mit->second.end(); it++)
	{
	  //CatalogEntry*		entry;
	  //entry = this->catalogEntry((*it)->offset(), (*it)->entrySize());
	  //std::cout << "Parent id: " << (*it)->parentId() << " -- id: " << (*it)->fsId() << std::endl;
	  //entry->catalogKey()->hexdump(1, 1);
	  this->__handler->mountPoint()->addChild(*it);
	  if ((*it)->isDir())
	    {
	      std::cout << "Recurse on: " << (*it)->fsId() << std::endl;
	      this->__linkNodes((*it), (*it)->fsId());
	    }
	}
      mit->second.clear();
    }
  for (mit = this->__nodes.begin(); mit != this->__nodes.end(); mit++)
    if (mit->second.size() > 0)
      ;//std::cout << "orphan entry found: " << mit->first << std::endl;
}


CatalogEntry*		CatalogTree::catalogEntry(uint64_t offset, uint16_t size)
{
  CatalogEntry*		entry;

  if (this->__version == 0)
    entry = new HfsCatalogEntry();
  else
    entry = new HfspCatalogEntry();
  entry->setSizeofKeyLengthField(this->sizeOfKey());
  try
    {
      //std::cout << offset << " -- " << size << std::endl;
      entry->process(this->_origin, offset, size);
    }
  catch (std::string err)
    {
      //std::cout << err << std::endl;
    }
  return entry;
}


void			CatalogTree::__progress(uint64_t current)
{
  uint64_t		percent;
  std::stringstream	sstr;

  percent = (current * 100) / this->totalNodes();
  if (this->__percent < percent)
    {
      sstr << "Processing nodes in catalog tree: " << percent << "% (" << current << " / " << this->totalNodes() << ")" << std::endl;
      this->__handler->setStateInformation(sstr.str());
      //this->__fsobj->stateinfo = sstr.str();
      sstr.str("");
      this->__percent = percent;
    }
}


void				CatalogTree::__makeNodes(Node* catalog, CatalogTreeNode* cnode)
{
  KeyedRecords			records;
  KeyedRecords::iterator	rit;
  CatalogEntry*			ckey;
  HfsNode*			node;

  records = cnode->records();
  for (rit = records.begin(); rit != records.end(); rit++)
    {
      if (*rit != NULL)
	{
	  node = NULL;
	  if ((ckey = dynamic_cast<CatalogEntry*>(*rit)) != NULL)
	    {
	      //ckey->catalogKey()->hexdump(1, 1);
	      //ckey->catalogData()->hexdump(1, 1);
	      //std::cout << "ParentId: " << ckey->parentId() << std::endl;
	      //std::cout << "id: " << ckey->id() << " - " << std::hex << ckey->id() << std::endl;
	      if (ckey->type() == CatalogEntry::FileRecord)
	      	{
	      	  this->__fileCount++;
	      	  node = new HfsFile(ckey->name(), this->__handler, ckey->offset(), ckey->size());
	      	  node->setFile();
	      	}
	      else if (ckey->type() == CatalogEntry::FolderRecord)
	      	{
	      	  this->__folderCount++;
	      	  node = new HfsFolder(ckey->name(), this->__handler, ckey->offset(), ckey->size());
	      	  node->setDir();
	      	}
	      if (node != NULL)
		this->__nodes[ckey->parentId()].push_back(node);
	    }
	  delete *rit;
	}
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
	  if ((*it)->isDir())
	    this->__linkNodes((*it), (*it)->fsId());
	  else
	    ;//this->__registerAllocatedBlocks(*it);
	}
      mit->second.clear();
    }
  else
    {
      std::cout << "Orphan entry detected" << std::endl;
    }
}


void	CatalogTree::__registerAllocatedBlocks(HfsNode* node)
{
  // HfsFile*		file;
  // ForkData*		fork;
  // ExtentsList           extents;
  // ExtentsList::iterator it;
  // uint64_t		bcount;
  // uint64_t		sblock;

  // if (node->isFile())
  //   {
  //     file = dynamic_cast<HfsFile*>(node);
  //     fork = file->dataFork();
  //     extents = fork->extents();
  //     for (it = extents.begin(); it != extents.end(); it++)
  // 	{
  // 	  sblock = (*it)->startBlock();
  // 	  this->__allocatedBlocks->insert(sblock);
  // 	  for (bcount = 0; bcount != (*it)->blockCount(); ++bcount)
  // 	    this->__allocatedBlocks->insert(sblock++);
  // 	}
  //     delete fork;
  //   }
}
