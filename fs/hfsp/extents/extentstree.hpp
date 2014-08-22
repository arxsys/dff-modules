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

#ifndef __HFSP_EXTENTS_TREE_HPP__
#define __HFSP_EXTENTS_TREE_HPP__

#include <stdint.h>

#include "export.hpp"
#include "node.hpp"

#include "endian.hpp"
#include "fork.hpp"
#include "htree.hpp"

typedef struct s_fork_data fork_data;

class ForkData;

PACK_START
typedef struct	s_extent_key
{
  uint16_t	keyLength;
  uint8_t	forkType;
  uint8_t	pad;
  uint32_t	fileId;
  uint32_t	startBlock;
}		extent_key;
PACK_END


class ExtentKey : public KeyedRecord
{
private:
  extent_key	__ekey;
public:
  ExtentKey();
  ~ExtentKey();
  void			process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  uint8_t		forkType();
  uint32_t		fileId();
  uint32_t		startBlock();
  fork_data*		forkData();
};


class ExtentTreeNode : public HNode
{
private:
  ExtentKey*	__createExtentKey(uint16_t start, uint16_t end);
public:
  ExtentTreeNode();
  ~ExtentTreeNode();
  virtual void				process(Node* origin, uint64_t uid, uint16_t size) throw (std::string);
  virtual KeyedRecords			records();
  bool					exists(uint32_t fileId, uint8_t type);
  std::map<uint32_t, fork_data * >	forksById(uint32_t fileId, uint8_t type);
};


class ExtentsTree : public HTree
{
private:
  Node*			__origin;
  uint64_t		__bsize;
public:
  ExtentsTree();
  ~ExtentsTree();
  void					process(Node* origin, uint64_t offset) throw (std::string);
  std::map<uint32_t, fork_data* >	forksById(uint32_t fileid, uint8_t type);
  uint64_t				blockSize();
  void					setBlockSize(uint64_t bsize);
};

#endif
