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

#include "extentstree.hpp"


ExtentsTree::ExtentsTree(uint8_t version) : __version(version), __bsize(4096), __origin(NULL)
{
}


ExtentsTree::~ExtentsTree()
{
}


void		ExtentsTree::process(Node* origin, uint64_t offset) throw (std::string)
{
  HTree::process(origin, offset);
}


void	ExtentsTree::setBlockSize(uint64_t bsize)
{
  this->__bsize = bsize;
}


uint64_t	ExtentsTree::blockSize()
{
  return this->__bsize;
}


std::map<uint32_t, fork_data *>		ExtentsTree::forksById(uint32_t fileid, uint8_t type)
{
  uint64_t				idx;
  ExtentTreeNode*			enode;
  std::map<uint32_t, fork_data *>	forks;
  std::map<uint32_t, fork_data *>	nodeforks;

  enode = NULL;
  if ((enode = new ExtentTreeNode(this->__version)) == NULL)
    throw std::string("Cannot create extent node");
  for (idx = 0; idx < this->totalNodes(); idx++)
    {
      try
   	{
   	  enode->process(this->_origin, idx, this->nodeSize());
	  nodeforks = enode->forksById(fileid, type);
	  forks.insert(nodeforks.begin(), nodeforks.end());
	}
      catch (std::string err)
  	{
  	  std::cout << "ERROR " << err << std::endl;
  	}
    }
  if (enode != NULL)
    delete enode;
  return forks;
}


ExtentTreeNode::ExtentTreeNode(uint8_t version) : __version(version)
{
  
}


ExtentTreeNode::~ExtentTreeNode()
{
  
}


void	ExtentTreeNode::process(Node* origin, uint64_t uid, uint16_t size) throw (std::string)
{
  HNode::process(origin, uid, size);
}


KeyedRecords	ExtentTreeNode::records()
{
  std::string	error;
  KeyedRecord*	record;
  KeyedRecords	records;
  int		i;
  

  if (this->isLeafNode() && (this->numberOfRecords() > 0))
    {
      for (i = this->numberOfRecords(); i > 0; i--)
	{
	  record = this->__createExtentKey(bswap16(this->_roffsets[i]), bswap16(this->_roffsets[i-1]));
	  records.push_back(record);
	}
    }
  else
    records = HNode::records();
  return records;  
}


std::map<uint32_t, fork_data * >	ExtentTreeNode::forksById(uint32_t fileId, uint8_t type)
{
  std::map<uint32_t, fork_data * >	forks;
  fork_data*				fork;
  ExtentKey*				record;
  int					i;

  if (this->isLeafNode() && (this->numberOfRecords() > 0))
    {
      for (i = this->numberOfRecords(); i > 0; i--)
	{
	  if ((record = this->__createExtentKey(bswap16(this->_roffsets[i]), bswap16(this->_roffsets[i-1]))) != NULL)
	    {
	      if (record->fileId() == fileId && record->forkType() == type)
		{
		  if ((fork = record->forkData()) != NULL)
		    forks[record->startBlock()] = fork;
		}
	      delete record;
	    }
	}
    }
  return forks;
}


bool	ExtentTreeNode::exists(uint32_t fileId, uint8_t type)
{
  std::string	error;
  ExtentKey*	record;
  KeyedRecords	records;
  int		i;
  bool		found;

  found = false;
  if (this->isLeafNode() && (this->numberOfRecords() > 0))
    {
      for (i = this->numberOfRecords(); i > 0; i--)
	{
	  if ((record = this->__createExtentKey(bswap16(this->_roffsets[i]), bswap16(this->_roffsets[i-1]))) != NULL)
	    {
	      if (record->fileId() == fileId && record->forkType() == type)
		found = true;
	      delete record;
	    }
	}
    }
  return found;
}


ExtentKey*	ExtentTreeNode::__createExtentKey(uint16_t start, uint16_t end)
{
  ExtentKey*	record;
  uint64_t	offset;
  uint16_t	size;

  offset = this->offset() + start;
  size = 0;
  if (start < end)
    size = end - start;
  if (this->__version == 0)
    record = new HfsExtentKey();
  else //if (this->__version == 1)
    record = new HfspExtentKey();
  record->process(this->_origin, offset, size);
  return record;
}



HfsExtentKey::HfsExtentKey() : __ekey()
{
}


HfsExtentKey::~HfsExtentKey()
{
}


void	HfsExtentKey::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  uint8_t*	key;

  KeyedRecord::process(origin, offset, size);
  key = NULL;
  if (((key = this->key()) != NULL) && (this->keyDataLength() >= sizeof(hfs_extent_key)))
    memcpy(&this->__ekey, key, sizeof(hfs_extent_key));
  if (key != NULL)
   free(key);
}


fork_data*	HfsExtentKey::forkData()
{
  uint8_t*	data;
  fork_data*	fork;
  hfs_extent	extents[3];
  uint8_t	i;
  uint32_t	blockCount;

  blockCount = 0; 
  data = NULL;
  fork = NULL;
  if ((this->dataLength() >= sizeof(hfs_extent)*3) && ((data = this->data()) != NULL)
      && ((fork = (fork_data*)malloc(sizeof(fork_data))) != NULL))
    {
      for (i = 0; i != 3; ++i)
	{
	  memcpy(&extents, data, sizeof(hfs_extent)*3);
	  fork->extents[i].startBlock = bswap32((uint32_t)bswap16(extents[i].startBlock));
	  fork->extents[i].blockCount = bswap32((uint32_t)bswap16(extents[i].blockCount));
	  blockCount += (uint32_t)bswap16(extents[i].blockCount);
	}
      fork->logicalSize = 0;
      fork->totalBlocks = bswap32(blockCount);
      fork->clumpSize = 0;
    }
  if (data != NULL)
    free(data);
  return fork;
}


uint8_t		HfsExtentKey::forkType()
{
  return this->__ekey.forkType;
}


uint32_t	HfsExtentKey::fileId()
{
  return bswap32(this->__ekey.fileId);
}


uint32_t	HfsExtentKey::startBlock()
{
  return bswap32((uint32_t)this->__ekey.startBlock);
}



HfspExtentKey::HfspExtentKey() : __ekey()
{
}


HfspExtentKey::~HfspExtentKey()
{
}


void	HfspExtentKey::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  uint8_t*	key;

  KeyedRecord::process(origin, offset, size);
  key = NULL;
  if (((key = this->key()) != NULL) && (this->keyDataLength() >= sizeof(hfsp_extent_key)))
    memcpy(&this->__ekey, key, sizeof(hfsp_extent_key));
  if (key != NULL)
   free(key);
}


fork_data*	HfspExtentKey::forkData()
{
  uint8_t*	data;
  fork_data*	fork;
 
  data = NULL;
  fork = NULL;
  if ((this->dataLength() >= sizeof(hfsp_extent)*8) && ((data = this->data()) != NULL)
      && ((fork = (fork_data*)malloc(sizeof(fork_data))) != NULL))
    {
      fork->logicalSize = 0;
      fork->clumpSize = 0;
      fork->totalBlocks = 0;
      memcpy(fork->extents, data, sizeof(hfsp_extent)*8);
    }
  if (data != NULL)
    free(data);
  return fork;
}


uint8_t		HfspExtentKey::forkType()
{
  return this->__ekey.forkType;
}


uint32_t	HfspExtentKey::fileId()
{
  return bswap32(this->__ekey.fileId);
}


uint32_t	HfspExtentKey::startBlock()
{
  return bswap32(this->__ekey.startBlock);
}

