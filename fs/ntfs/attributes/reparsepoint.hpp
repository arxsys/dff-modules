/* 
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
 * 
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
 *  Christophe Malinge <cma@digital-forensic.org>
 *
 */

#ifndef __REPARSEPOINT_HPP__
#define __REPARSEPOINT_HPP__

#include "common.hpp"
#include "attribute.hpp"


/**
 * $SYMBOLINK_LINK_OR_REPARSE_POINT attribute
 */

PACK_START
typedef struct	s_AttributeReparsePoint
{
  uint32_t	flags;
  uint16_t	reparseDataSize;
  uint16_t	unused;
  uint16_t	targetNameOffset;
  uint16_t	targetNameLength;
  uint16_t	targetPrintNameOffset;
  uint16_t	targetPrintNameLength;
}		AttributeReparsePoint_t;
PACK_END

class AttributeReparsePoint : Attribute
{
public:
  AttributeReparsePoint(Attribute &);
  ~AttributeReparsePoint();
  void	content();


private:
  AttributeReparsePoint_t	*_data;
};

#endif
