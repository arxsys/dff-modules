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


ExtentKey::ExtentKey()
{
}


ExtentKey::~ExtentKey()
{
}


void	ExtentKey::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  uint8_t*	key;

  KeyedRecord::process(origin, offset, size);
  key = NULL;
  if (((key = this->key()) != NULL) && (this->keyDataLength() >= sizeof(extent_key)))
    memcpy(&this->__ekey, key, sizeof(extent_key));
  if (key != NULL)
    free(key);
}


uint32_t	ExtentKey::fileId()
{
  return bswap32(this->__ekey.fileId);
}



uint32_t	ExtentKey::startBlock()
{
  return bswap32(this->__ekey.startBlock);
}



ExtentTreeNode::ExtentTreeNode()
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


std::vector<fork_data* >	ExtentTreeNode::forkById(uint32_t fileId)
{
  std::vector<fork_data* >     forks;
  
  return forks;
}


bool	ExtentTreeNode::exists(uint32_t fileId)
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
	  record = this->__createExtentKey(bswap16(this->_roffsets[i]), bswap16(this->_roffsets[i-1]));
	  if (record->fileId() == fileId)
	    found = true;
	  delete record;
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
  record = new ExtentKey();
  record->setOrigin(this->_origin);
  record->setOffset(offset);
  record->setSize(size);
  return record;
}





ExtentsTree::ExtentsTree()
{
  this->__bsize = 4096; // default to 4096
}


ExtentsTree::~ExtentsTree()
{
}



void		ExtentsTree::process(Node* origin, uint64_t offset) throw (std::string)
{
  HTree::process(origin, offset);
}


std::vector<fork_data *>	ExtentsTree::forkById(uint32_t fileid)
{
  uint64_t				idx;
  ExtentTreeNode*			enode;
  std::vector<fork_data *>		ret;

  if ((enode = new ExtentTreeNode()) == NULL)
    throw std::string("Cannot create extent node");
  for (idx = 0; idx < this->totalNodes(); idx++)
    {
      try
   	{
   	  enode->process(this->_origin, idx, this->nodeSize());
	  if (enode->isLeafNode() && enode->exists(fileid))
	    {
	      ret = enode->forkById(fileid);
	    }
	}
      catch (std::string err)
  	{
  	  std::cout << "ERROR " << err << std::endl;
  	}
    }
  return ret;
}


void	ExtentsTree::setBlockSize(uint64_t bsize)
{
  this->__bsize = bsize;
}


uint64_t	ExtentsTree::blockSize()
{
  return this->__bsize;
}
