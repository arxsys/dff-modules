/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: *www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Solal Jacob <sja@digital-forensic.org>
 */

#ifndef __REGISTRY_HH__
#define __REGISTRY_HH__

#include "mfso.hpp"

namespace Destruct
{
class DObject;
}

namespace DFF
{
class Node;
}

class Registry : public DFF::mfso
{
public:
  Registry();
  ~Registry();

  void                  start(DFF::Attributes args);
  void                  createNodeTree(Destruct::DObject* regf);
  void                  createKeyNode(Destruct::DObject* regf, DFF::Node* parent);
  void                  setStateInfo(const std::string& info);
  Destruct::DObject*    open(void);
  DFF::Node*            rootNode(void) const;
private:
  DFF::Node*            __rootNode;
};


#endif
