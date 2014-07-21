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

#include "fork.hpp"


ForkData::ForkData(uint64_t blocksize)
{
  memset(&this->__fork, 0, sizeof(fork_data));
  this->__etree = NULL;
  this->__blocksize = blocksize;
  this->__initialSize = 0;
  this->__fileId = 0;
}


ForkData::~ForkData()
{
  this->__clearExtents();
}


void		ForkData::setFileId(uint32_t fileId)
{
  this->__fileId = fileId;
}


void		ForkData::setInitialFork(fork_data fork)
{
  int		i;
  Extent*	ext;
  
  this->__fork = fork;
  this->__clearExtents();
  this->__initialSize = 0;
  for (i = 0; i < 8; i++)
    {
      ext = new Extent(fork.extents[i], this->__blocksize);
      this->__initialSize += ext->size();
      this->__extents.push_back(ext);
    }
  if (this->__initialSize < this->logicalSize())
    {
      // std::cout << "this is the case for: " << this->__fileId << std::endl;
      // if (this->__etree != NULL)
      // 	{
      // 	  std::vector<fork_data* > ret = this->__etree->forkById(this->__fileId);
      // 	}
      // else
      // 	std::cout << "[!] No Extents Overflow File set. Resulting data will be truncated" << std::endl;
    }
  // else if (initsize > this->logicalSize())
  //   std::cout << "[!] Size of initial extents is greater than set logical size" << std::endl;
}


void		ForkData::setExtentsTree(ExtentsTree* etree)
{
  this->__etree = etree;
}


uint64_t	ForkData::initialForkSize()
{
  return this->__initialSize;
}


uint64_t	ForkData::logicalSize()
{
  return bswap64(this->__fork.logicalSize);
}


uint32_t	ForkData::clumpSize()
{
  return bswap32(this->__fork.clumpSize);
}


uint32_t	ForkData::totalBlocks()
{
  return bswap32(this->__fork.totalBlocks);
}


uint64_t	ForkData::allocatedBytes()
{
  uint64_t	bytes;

  bytes = (uint64_t)this->totalBlocks();
  bytes *= 4096;
  return bytes;
}


uint64_t	ForkData::slackSize()
{
  uint64_t	allocated;
  uint64_t	size;

  size = this->logicalSize();
  allocated = this->allocatedBytes();
  if (size <= allocated)
    return allocated - size;
  else
    return 0;
}


ExtentsList	ForkData::extents()
{
  return this->__extents;
}


Extent*		ForkData::getExtent(uint32_t id)
{
  if (id < this->__extents.size() - 1)
    return this->__extents[id];
  else
    return NULL;
}


void		ForkData::dump(std::string tab)
{
  unsigned int	i;
  uint64_t	bcount;
  
  std::cout << tab << "logical size: " << this->logicalSize() << std::endl;
  std::cout << tab << "clump size: " << this->clumpSize() << std::endl;
  std::cout << tab << "total blocks: " << this->totalBlocks() << std::endl;
  std::cout << tab << "allocated bytes: " << this->allocatedBytes()  << std::endl;
  std::cout << tab << "slack size: " << this->slackSize()  << std::endl;
  std::cout << tab << "Extent information" << std::endl;
  
  bcount = 0;
  for (i = 0; i < this->__extents.size(); i++)
    {
      //std::cout << tab << "Extent " << i << std::endl;
      //this->__extents[i]->dump("\t\t");
      bcount += this->__extents[i]->blockCount();
    }
  std::cout << tab << "Missing blocks " << bcount << std::endl;
}


void	ForkData::__clearExtents()
{
  unsigned int	i;

  for (i = 0; i < this->__extents.size(); i++)
    delete this->__extents[i];
  this->__extents.clear();
}
