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

#ifndef __BITMAP_HH__ 
#define __BITMAP_HH__

#include "ntfs_common.hpp"
#include "mftattributecontent.hpp"

class Bitmap : public MFTAttributeContent
{
public:
  Bitmap(MFTAttribute* mftAttribute);
  ~Bitmap();
  static MFTAttributeContent*	create(MFTAttribute* mftAttribute);
  const std::string             typeName(void) const;
  Attributes                    _attributes(void);
};

#endif
