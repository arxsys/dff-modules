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

#ifndef __IPART_HPP__
#define __IPART_HPP__

#include "exceptions.hpp"
#include "fso.hpp"
#include "filemapping.hpp"
#include "node.hpp"

#include <stdint.h>

using namespace DFF;

class PartInterface
{
public:
  virtual		~PartInterface(){}
  virtual bool		process(Node* origin, uint64_t offset, uint32_t sectsize) throw (vfsError) = 0;
  virtual void		makeNodes(Node* root, fso* fsobj) = 0;
  virtual Attributes	result() = 0;
  virtual Attributes	entryAttributes(uint64_t entry, uint8_t type) = 0;
  virtual void		mapping(FileMapping* fm, uint64_t entry, uint8_t type) = 0;
  virtual uint32_t	entriesCount() = 0;
  virtual uint64_t	lba(uint32_t which) = 0;
};

#endif
