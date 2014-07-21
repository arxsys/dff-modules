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

#ifndef __ALLOCATION_HPP__
#define __ALLOCATION_HPP__

#include <stdint.h>

#include "export.hpp"
#include "node.hpp"
#include "vfile.hpp"

#include "endian.hpp"
#include "extents/fork.hpp"


class AllocationFile
{
private:
  Node*		__allocation;
  Node*		__origin;
  Node*		__mountpoint;
  fso*		__fsobj;
  ExtentsTree*	__etree;
  VFile*	__vfile;
  uint8_t*	__cache;
  uint64_t	__cacheOffset;
  std::map<uint64_t, uint64_t>	__freeBlocks;
  uint64_t	__blocks;

  void			__initCache();
  void			__clearCache();
  void			__updateCache(uint64_t offset);
public:
  AllocationFile();
  ~AllocationFile();
  void			setFso(fso* fsobj);
  void			setOrigin(Node* origin) throw (std::string);
  void			setMountPoint(Node* mountpoint) throw (std::string);
  void			setExtentsTree(ExtentsTree* etree) throw (std::string);
  void			process(Node* allocation, uint64_t offset, uint64_t blocks) throw (std::string);
  bool			isBlockAllocated(uint64_t block) throw (std::string);
};


class UnallocatedNode : public Node
{
private:
  std::map<uint64_t, uint64_t>	__freeBlocks;
  Node*				__origin;
  uint64_t			__bsize;
public:
  UnallocatedNode(std::string name, uint64_t size, Node* parent, fso* fsobj);
  ~UnallocatedNode();
  void	setContext(Node* origin, uint64_t bsize, const std::map<uint64_t, uint64_t>& freeBlocks);
  void	fileMapping(FileMapping* fm);
};


#endif 
