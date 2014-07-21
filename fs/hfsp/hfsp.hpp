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

#ifndef __HFSP_HPP__
#define __HFSP_HPP__

#include <map>

#include "variant.hpp"
#include "mfso.hpp"
#include "node.hpp"

#include "volume/volume.hpp"
#include "extents/fork.hpp"
#include "allocation.hpp"

class Hfsp : public mfso
{
private:
  void			__process() throw (std::string);
  void			__setContext(std::map<std::string, Variant_p > args) throw (std::string);
  Node*			__parent;
  class HfsRootNode*	__root;
  ExtentsTree*		__createEtree(VolumeHeader* volume) throw (std::string);
  AllocationFile*	__createAllocation(VolumeHeader* volume, ExtentsTree* etree) throw (std::string);
  void			__createCatalog(VolumeHeader* volume, ExtentsTree* etree) throw (std::string);
public:
  Hfsp();
  ~Hfsp();
  virtual void	start(std::map<std::string, Variant_p > args);
};


class HfsRootNode: public Node
{
private:
  VolumeHeader*	__vheader;
public:
  HfsRootNode(std::string name, uint64_t size, Node* parent, fso* fsobj) : Node(name, size, parent, fsobj) {}
  HfsRootNode() {}
  void		setVolumeHeader(VolumeHeader* vheader);
  Attributes	_attributes();
};

#endif
