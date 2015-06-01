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
typedef struct	s_hfs_extent_key
{
  uint8_t	keyLength;
  uint8_t	forkType;
  uint32_t	fileId;
  uint16_t	startBlock;
}		hfs_extent_key;
PACK_END


PACK_START
typedef struct	s_hfsp_extent_key
{
  uint16_t	keyLength;
  uint8_t	forkType;
  uint8_t	pad;
  uint32_t	fileId;
  uint32_t	startBlock;
}		hfsp_extent_key;
PACK_END


// class ExtentsTreeFactory
// {
// public:
//   enum Version
//     {
//       Hfs	= 0,
//       Hfsp	= 1,
//     }
//   ExtentsTreeFactory();
//   ~ExtentsTreeFactory();
//   ExtentsTree*	createExtentTree(Version version) throw (std::string);
// };


class ExtentsTree : public HTree
{
private:
  uint8_t				__version;
  uint64_t				__bsize;
  Node*					__origin;
public:
  ExtentsTree(uint8_t version);
  ~ExtentsTree();
  virtual void				process(Node* origin, uint64_t offset) throw (std::string);
  std::map<uint32_t, fork_data* >	forksById(uint32_t fileid, uint8_t type);
  uint64_t				blockSize();
  void					setBlockSize(uint64_t bsize);
};


// class ExtentsTree : public HTree
// {
// protected:
//   Node*			_origin;
//   uint64_t		_bsize;
// public:
//   virtual ~ExtentsTree();
//   virtual void				process(Node* origin, uint64_t offset) throw (std::string);
//   std::map<uint32_t, fork_data* >	forksById(uint32_t fileid, uint8_t type) = 0;
//   uint64_t				blockSize();
//   void					setBlockSize(uint64_t bsize);
// };


// class HfsExtentsTree : public ExtentsTree
// {
// public:
//   HfsExtentsTree();
//   ~HfsExtentsTree();
//   virtual void				process(Node* origin, uint64_t offset) throw (std::string);
// };


// class HfspExtentsTree : public ExtentsTree
// {
// public:
//   HfspExtentsTree();
//   ~HfspExtentsTree();
//   virtual void				process(Node* origin, uint64_t offset) throw (std::string);
// };


class ExtentTreeNode : public HNode
{
private:
  uint8_t				__version;
  class ExtentKey*			__createExtentKey(uint16_t start, uint16_t end);
public:
  ExtentTreeNode(uint8_t version);
  ~ExtentTreeNode();
  void					process(Node* origin, uint64_t uid, uint16_t size) throw (std::string);
  KeyedRecords				records();
  bool					exists(uint32_t fileId, uint8_t type);
  std::map<uint32_t, fork_data * >	forksById(uint32_t fileId, uint8_t type);
};


// class HfsExtentTreeNode : public ExtentTreeNode
// {
// private:
//   ExtentKey*	__createExtentKey(uint16_t start, uint16_t end);
// public:
//   ExtentTreeNode();
//   ~ExtentTreeNode();
//   virtual void				process(Node* origin, uint64_t uid, uint16_t size) throw (std::string);
//   virtual KeyedRecords			records();
// };


// class HfspExtentTreeNode : public ExtentTreeNode
// {
// private:
//   ExtentKey*	__createExtentKey(uint16_t start, uint16_t end);
// public:
//   ExtentTreeNode();
//   ~ExtentTreeNode();
//   virtual void				process(Node* origin, uint64_t uid, uint16_t size) throw (std::string);
//   virtual KeyedRecords			records();
// };


class ExtentKey : public KeyedRecord
{
public:
  ExtentKey() {}
  virtual ~ExtentKey() {}
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string) = 0;
  virtual fork_data*	forkData() = 0;
  virtual uint8_t	forkType() = 0;
  virtual uint32_t	fileId() = 0;
  virtual uint32_t	startBlock() = 0;
};


class HfsExtentKey : public ExtentKey
{
private:
  hfs_extent_key	__ekey;
public:
  HfsExtentKey();
  ~HfsExtentKey();
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  virtual fork_data*	forkData();
  virtual uint8_t	forkType();
  virtual uint32_t	fileId();
  virtual uint32_t	startBlock();
};


class HfspExtentKey : public ExtentKey
{
private:
  hfsp_extent_key	__ekey;
public:
  HfspExtentKey();
  ~HfspExtentKey();
  virtual void		process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  virtual fork_data*	forkData();
  virtual uint8_t	forkType();
  virtual uint32_t	fileId();
  virtual uint32_t	startBlock();
};


#endif
