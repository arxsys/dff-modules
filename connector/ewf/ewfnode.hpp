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
 *  Solal Jacob <sja@digital-forensic.org>
 */

#ifndef __EWFNODE_HPP__
#define __EWFNODE_HPP__

#include "typesconv.hpp"
#include "ewf.hpp"
#include <iostream>

class EWFNode : public Node
{
private:
  std::string	__getHashIdentifier(uint32_t index) throw();
  std::string	__getHashValue(std::string identifier) throw ();
  std::string	__getIdentifier(uint32_t index) throw ();
  std::string	__getValue(std::string identifier) throw ();
public:
  EWFNode(std::string name, uint64_t size, Node* parent, class ewf* fsobj, std::list<Variant_p > originalPath);
  ~EWFNode();
  ewf*                          ewfso;
  std::list<Variant_p >		originalPath;
  virtual Attributes	_attributes();
};
#endif
