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


ForkData::ForkData(uint32_t fileid, uint64_t blocksize) : __fileId(fileid), __blockSize(blocksize), __initialSize(0), __extendedSize(0), __etree(NULL)
{
}

ForkData::ForkData(uint32_t fileid, ExtentsTree* etree) : __fileId(fileid), __blockSize(0), __initialSize(0), __extendedSize(0), __etree(etree)
{
  if (etree != NULL)
    this->__blockSize = this->__etree->blockSize();
}

ForkData::~ForkData()
{
  this->__clearExtents();
}


void		ForkData::process(Node* origin, uint64_t offset, ForkData::Type type) throw (std::string)
{
  fork_data	fork;

  if (this->__readToBuffer(&fork, sizeof(fork_data), origin, offset))
    this->process(fork, type);
  else
    throw std::string("ForkData: cannot read fork_data structure");
}


void		ForkData::process(fork_data initial, ForkData::Type type) throw (std::string)
{
  std::map<uint32_t, fork_data* >		forks;
  std::map<uint32_t, fork_data* >::iterator	mit;
  uint64_t					size;

  if (this->__blockSize == 0)
    return;
  this->__fork = initial;
  this->__clearExtents();
  this->__type = type;
  this->__initialSize = this->__processFork(initial);
  this->__extendedSize = 0;
  if (this->__initialSize < this->logicalSize())
    {
      if (this->__etree != NULL)
      	{
	  forks = this->__etree->forksById(this->__fileId, type);
	  for (mit = forks.begin(); mit != forks.end(); mit++)
	    {
	      if (mit->second != NULL)
		{
		  size = this->__processFork(*(mit->second));
		  this->__extendedSize += size;
		}
	    }
      	}
      else
      	std::cout << "[!] No Extents Overflow File set. Resulting data will be truncated" << std::endl;
    }
  else
    ; // too many forks !
}


void		ForkData::setBlockSize(uint64_t blocksize)
{
  //XXX check if coherent
  this->__blockSize = blocksize;
}


void		ForkData::setExtentsTree(ExtentsTree* etree)
{
  if (etree != NULL)
    this->__etree = etree;
}


void		ForkData::setFileId(uint32_t fileId)
{
  this->__fileId = fileId;
}


uint64_t	ForkData::__processFork(fork_data fork)
{
  int		i;
  Extent*	ext;
  uint64_t	size;

  size = 0;
  for (i = 0; i < 8; i++)
    {
      ext = new Extent(fork.extents[i], this->__blockSize);
      if (ext->size() > 0)
	{
	  size += ext->size();
	  this->__extents.push_back(ext);
	}
      else
	delete ext;
    }
  return size;
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


bool	ForkData::__readToBuffer(void* buffer, uint16_t size, Node* origin, uint64_t offset)
{
  bool		success;
  VFile*	vfile;
  
  vfile = NULL;
  success = true;
  try
    {
      vfile = origin->open();
      vfile->seek(offset);
      if (vfile->read(buffer, size) != size)
	success = false;
    }
  catch (std::string& err)
    {
      success = false;
    }
  catch (vfsError& err)
    {
      success = false;
    }
  if (vfile != NULL)
    {
      vfile->close();
      delete vfile;
    }
  return success;
}


void	ForkData::__clearExtents()
{
  unsigned int	i;

  for (i = 0; i < this->__extents.size(); i++)
    delete this->__extents[i];
  this->__extents.clear();
}
