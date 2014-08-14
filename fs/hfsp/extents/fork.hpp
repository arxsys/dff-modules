/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2014 ArxSys
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

#ifndef __HFSP_FORK_HPP__
#define __HFSP_FORK_HPP__

#include <stdint.h>
#include <vector>

#include "export.hpp"

#include "extent.hpp"
#include "extentstree.hpp"

#include "specialfile.hpp"

PACK_START
typedef struct s_fork_data 
{
  uint64_t	logicalSize;
  uint32_t	clumpSize;
  uint32_t	totalBlocks;
  extent	extents[8];
}		fork_data;
PACK_END

class ExtentsTree;

typedef std::vector<Extent*> ExtentsList;

class ForkData
{
public:
  ForkData(uint32_t fileid, uint64_t blocksize); // special case for ExtentsTree file
  ForkData(uint32_t fileid, ExtentsTree* etree);
  ~ForkData();
  typedef enum
    {
      Data	= 0x00,
      Resource	= 0xFF
    } Type;
  void		setBlockSize(uint64_t blocksize);
  void		setExtentsTree(ExtentsTree* efile);
  void		setFileId(uint32_t fileId);
  void		process(Node* origin, uint64_t offset, ForkData::Type type) throw (std::string);
  void		process(fork_data fork, ForkData::Type type) throw (std::string);
  uint64_t	initialForkSize();
  void		dump(std::string tab);
  uint64_t	logicalSize();
  uint32_t	clumpSize();
  uint32_t	totalBlocks();
  uint64_t	allocatedBytes();
  uint64_t	slackSize();
  Extent*	getExtent(uint32_t id);
  ExtentsList	extents();

private:
  uint32_t		__fileId;
  uint64_t		__blockSize;
  uint64_t		__initialSize;
  uint64_t		__extendedSize;
  ForkData::Type	__type;
  class ExtentsTree*	__etree;
  fork_data		__fork;
  std::vector<Extent* >	__extents;

  bool			__readToBuffer(void* buffer, uint16_t size, Node* origin, uint64_t offset);
  void			__clearExtents();
  uint64_t		__processFork(fork_data fork);
};


#endif
