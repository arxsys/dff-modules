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

#include "bitmap.hpp"
#include "mftattribute.hpp"

Bitmap::Bitmap(MFTAttribute* mftAttribute) : MFTAttributeContent(mftAttribute)
{
}

MFTAttributeContent*	Bitmap::create(MFTAttribute*	mftAttribute)
{
  return (new Bitmap(mftAttribute));
}

Bitmap::~Bitmap()
{
}

const std::string       Bitmap::typeName(void) const
{
  return (std::string("$BITMAP"));
}
Attributes	Bitmap::_attributes(void)
{
  Attributes	attrs;

  MAP_ATTR("Attributes", MFTAttributeContent::_attributes())
  return (attrs);
}
