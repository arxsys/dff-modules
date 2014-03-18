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

#ifndef __ATTRIBUTE_LIST_HH__
#define __ATTRIBUTE_LIST_HH__

#include "ntfs_common.hpp"
#include "mftattributecontent.hpp"

//PACK_S FileName_s 
//{
//uint8_t		nameSpace;
//} PACK;

class AttributeList : public MFTAttributeContent
{
private:
  //FileName_s		__fileName;
public:
		        AttributeList(MFTAttribute* mftAttribute);
			~AttributeList();
  Attributes		_attributes(void);
  std::string		typeName(void);
  static MFTAttributeContent*	create(MFTAttribute* mftAttribute);
};

#endif
