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

typedef std::vector<Extent*> ExtentsList;

class ForkData
{
private:
  uint64_t		__initialSize;
  uint64_t		__blocksize;
  uint32_t		__fileId;
  fork_data		__fork;
  std::vector<Extent* >	__extents;
  class ExtentsTree*	__etree;
  void			__clearExtents();
public:
  ForkData(uint64_t blocksize);
  ~ForkData();
  void		setInitialFork(fork_data fork);
  void		setExtentsTree(ExtentsTree* efile);
  uint64_t	initialForkSize();
  void		dump(std::string tab);
  uint64_t	logicalSize();
  uint32_t	clumpSize();
  uint32_t	totalBlocks();
  uint64_t	allocatedBytes();
  uint64_t	slackSize();
  void		setFileId(uint32_t fileId);
  Extent*	getExtent(uint32_t id);
  ExtentsList	extents();
};


#endif
