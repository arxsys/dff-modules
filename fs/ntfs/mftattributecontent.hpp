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

#ifndef __MFT_ATTRIBUTE_CONTENT_HH__
#define __MFT_ATTRIBUTE_CONTENT_HH__

#include "ntfs_common.hpp"

class MFTAttribute;


struct RunListInfo 
{
  union 
  {
     uint8_t byte;
     struct {
	      uint8_t lengthSize:4;
	      uint8_t offsetSize:4;
     	    } info;
  };
};

class MFTAttributeContent : public Node
{
private:
  MFTAttribute*	__mftAttribute;
public:
  			MFTAttributeContent(MFTAttribute* mftAttribute);
	 		~MFTAttributeContent();
  Attributes		_attributes();
  void			fileMapping(FileMapping* fm);
  uint8_t*		data();
  uint16_t		typeID(void);
  std::string		attributeName(void);
  virtual std::string	typeName(void);
};

#endif