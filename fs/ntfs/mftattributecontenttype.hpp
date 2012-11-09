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

#ifndef __MFT_ATTRIBUTE_CONTENT_TYPE_HH__ 
#define __MFT_ATTRIBUTE_CONTENT_TYPE_HH__

#include "mftattribute.hpp"
#include "mftattributecontent.hpp"
#include "standardinformation.hpp"
#include "filename.hpp"

#define $STANDARD_INFORMATION   16	
#define $FILE_NAME		48
#define $DATA			128

typedef MFTAttributeContent* (*ContentObject)(MFTAttribute*);

struct ContentType
{
 uint32_t	ID;
 ContentObject	object;
};

ContentType const ContentTypes[] =
{
  { $STANDARD_INFORMATION, &StandardInformation::create },
  { $FILE_NAME, &FileName::create },
  { 0, NULL },
};
 
#endif
