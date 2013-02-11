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

#ifndef __FILE_NAME_HH__ 
#define __FILE_NAME_HH__

#include "ntfs_common.hpp"
#include "mftattributecontent.hpp"

#define FILENAME_NAMESPACE_POSIX 	0
#define FILENAME_NAMESPACE_WIN32 	1
#define FILENAME_NAMESPACE_DOS	 	2
#define FILENAME_NAMESPACE_DOS_WIN32 	3

PACK_S FileName_s 
{
  uint64_t		parentDirectoryReference;
  uint64_t		creationTime;
  uint64_t		modificationTime;
  uint64_t		mftModificationTime;
  uint64_t		accessedTime;
  uint64_t		allocatedSize;
  uint64_t		realSize;
  uint32_t		flags;
  uint32_t		reparseValue;
  uint8_t		nameLength;
  uint8_t		nameSpace;
;
 } PACK;

class FileName : public MFTAttributeContent
{
private:
  uint16_t*		__name;
  FileName_s		__fileName;
public:
		        FileName(MFTAttribute* mftAttribute);
			~FileName();
  uint64_t		parentDirectoryReference(void);
  vtime*		creationTime(void);
  vtime*		modificationTime(void);
  vtime*		mftModificationTime(void);
  vtime*		accessedTime(void);
  uint64_t		allocatedSize(void);
  uint64_t		realSize(void);
  std::list<Variant_p>	flags(void);
  uint32_t		reparseValue(void);
  uint8_t		nameLength(void);
  uint8_t		nameSpaceID(void);
  std::string		nameSpace(void);
  std::string		name(void); //utf 16 ? namespace
  Attributes		_attributes(void);
  std::string		typeName(void);
  static MFTAttributeContent*	create(MFTAttribute* mftAttribute);
};

#endif
