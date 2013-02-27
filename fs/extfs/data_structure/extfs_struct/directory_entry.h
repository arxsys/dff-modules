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
 *  Romain Bertholon <rbe@digital-forensic.org>
 *
 */

#ifndef __DIRECTORY_ENTRY_H__
#define __DIRECTORY_ENTRY_H__

//#include "types.h"

#ifdef WIN32
#define PACK
#else
#define PACK __attribute__ ((packed))
#endif

#ifdef WIN32
#pragma pack(1)
#endif

typedef	struct	__directory_entry_original_s
{
  uint32	inode_value;
  uint16	entry_length;
  uint16	name_length;
}PACK		dir_entry_v1;

typedef	struct	__directory_entry_2nd_version_s
{
  uint32	inode_value;
  uint16	entry_length;
  uchar		name_length;
  uchar		file_type;
}PACK		dir_entry_v2;

#endif
