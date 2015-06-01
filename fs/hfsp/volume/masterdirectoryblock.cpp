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


#include "volume.hpp"


MasterDirectoryBlock::MasterDirectoryBlock()
{
}


MasterDirectoryBlock::~MasterDirectoryBlock()
{
}


uint16_t	MasterDirectoryBlock::type()
{
  return HfsVolume;
}


void		MasterDirectoryBlock::process(Node* origin, uint64_t offset, fso* fsobj) throw (std::string)
{
  VFile*	vf;

  memset(&this->__mdb, 0, sizeof(master_dblock));
  if (origin == NULL)
    throw std::string("Provided node does not exist");
  try
    {
      vf = origin->open();
      vf->seek(offset);
      if (vf->read(&this->__mdb, sizeof(master_dblock)) != sizeof(master_dblock))
	{
	  vf->close();
	  delete vf;
	  throw std::string("Error while reading HFS Volume Header");
	}
    }
  catch (...)
    {
    }
  this->sanitize();
}


void		MasterDirectoryBlock::sanitize() throw (std::string)
{
  if ((this->blockSize() % 512) != 0)
    throw std::string("Block size is not a muliple of 512");
  if (this->totalBlocks() < this->freeBlocks())
    throw std::string("More free block than total blocks");
}


Attributes	MasterDirectoryBlock::_attributes()
{
  Attributes	vmap;

  //vmap["version"] = new Variant(this->version());
  //vmap["last mounted version"] = new Variant(this->lastMountedVersion());
  vmap["created"] = new Variant(this->createDate());
  vmap["modified"] = new Variant(this->modifyDate());
  vmap["backup"] = new Variant(this->backupDate());
  vmap["Total number of files"] = new Variant(this->fileCount());
  vmap["Total number of folders"] = new Variant(this->folderCount());
  vmap["number of files in root directory"] = new Variant(this->rootdirFiles());
  vmap["number of folders in root directory"] = new Variant(this->rootdirFolders());
  vmap["bitmap block"] = new Variant(this->volumeBitmapBlock());
  vmap["first allocation block"] = new Variant(this->firstAllocationBlock());
  vmap["backup sequence number"] = new Variant(this->backupSeqNumber());
  vmap["allocation block size"] = new Variant(this->blockSize());
  vmap["total number of allocation blocks"] = new Variant(this->totalBlocks());
  vmap["total number of free allocation blocks"] = new Variant(this->freeBlocks());
  vmap["total mounted"] = new Variant(this->writeCount());
  vmap["clump size"] = new Variant(this->clumpSize());
  vmap["embed signature"] = new Variant(this->embedSignature());
  return vmap;
}


uint32_t	MasterDirectoryBlock::totalBlocks()
{
  return (uint32_t)bswap16(this->__mdb.totalBlocks);
}


uint32_t	MasterDirectoryBlock::blockSize()
{
  return bswap32(this->__mdb.blockSize);
}


fork_data	MasterDirectoryBlock::extentsFile()
{
  fork_data	fork;
  uint8_t	i;
  uint64_t	logicalSize;
  uint32_t	blockCount;

  logicalSize = 0;
  blockCount = 0;
  memset(&fork, 0, sizeof(fork_data));
  for (i = 0; i != 3; ++i)
    {
      fork.extents[i].startBlock = bswap32((uint32_t)bswap16(this->__mdb.overflowExtents[i].startBlock));
      fork.extents[i].blockCount = bswap32((uint32_t)bswap16(this->__mdb.overflowExtents[i].blockCount));
      logicalSize += (((uint64_t)bswap16(this->__mdb.overflowExtents[i].blockCount)) * this->blockSize());
      blockCount += (uint32_t)bswap16(this->__mdb.overflowExtents[i].blockCount);
    }
  fork.logicalSize = bswap64(logicalSize);
  fork.totalBlocks = bswap32(blockCount);
  fork.clumpSize = 0;
  return fork;
}


fork_data	MasterDirectoryBlock::catalogFile()
{
  fork_data	fork;
  uint8_t	i;
  uint64_t	logicalSize;
  uint32_t	blockCount;

  logicalSize = 0;
  blockCount = 0;
  memset(&fork, 0, sizeof(fork_data));
  for (i = 0; i != 3; ++i)
    {
      fork.extents[i].startBlock = bswap32((uint32_t)bswap16(this->__mdb.catalogExtents[i].startBlock));
      fork.extents[i].blockCount = bswap32((uint32_t)bswap16(this->__mdb.catalogExtents[i].blockCount));
      logicalSize += (((uint64_t)bswap16(this->__mdb.catalogExtents[i].blockCount)) * this->blockSize());
      blockCount += (uint32_t)bswap16(this->__mdb.catalogExtents[i].blockCount);
    }
  fork.logicalSize = bswap64(logicalSize);
  fork.totalBlocks = bswap32(blockCount);
  fork.clumpSize = 0;
  return fork;

}



uint16_t	MasterDirectoryBlock::signature()
{
  return bswap16(this->__mdb.signature);
}


vtime*		MasterDirectoryBlock::createDate()
{
  uint32_t	cdate;

  cdate = bswap32(this->__mdb.createDate);
  return new HfsVtime(cdate);
}


vtime*		MasterDirectoryBlock::modifyDate()
{
  uint32_t	mdate;

  mdate = bswap32(this->__mdb.modifyDate);
  return new HfsVtime(mdate);
}
  

uint16_t	MasterDirectoryBlock::attributes()
{
  return bswap16(this->__mdb.attributes);
}


uint16_t	MasterDirectoryBlock::rootdirFiles()
{
  return bswap16(this->__mdb.rootdirFiles);
}


uint16_t	MasterDirectoryBlock::volumeBitmapBlock()
{
  return bswap16(this->__mdb.volumeBitmapBlock);
}


uint16_t	MasterDirectoryBlock::nextAllocationBlock()
{
  return bswap16(this->__mdb.nextAllocationBlock);
}


uint32_t	MasterDirectoryBlock::clumpSize()
{
  return bswap32(this->__mdb.clumpSize);
}


uint16_t	MasterDirectoryBlock::firstAllocationBlock()
{
  return bswap16(this->__mdb.firstAllocationBlock);
}


uint32_t	MasterDirectoryBlock::nextCatalogNodeId()
{
    return bswap32(this->__mdb.nextCatalogNodeId);
}

uint16_t	MasterDirectoryBlock::freeBlocks()
{
  return bswap16(this->__mdb.freeBlocks);
}


std::string	MasterDirectoryBlock::volumeName()
{
  return std::string(this->__mdb.volumeName, 28);
}


vtime*		MasterDirectoryBlock::backupDate()
{
  uint32_t	bdate;

  bdate = bswap32(this->__mdb.backupDate);
  return new HfsVtime(bdate);
}


uint16_t	MasterDirectoryBlock::backupSeqNumber()
{
  return bswap16(this->__mdb.backupSeqNumber);
}


uint32_t	MasterDirectoryBlock::writeCount()
{
  return bswap32(this->__mdb.writeCount);
}


uint32_t	MasterDirectoryBlock::OverflowClumpSize()
{
  return bswap32(this->__mdb.OverflowClumpSize);
}


uint32_t	MasterDirectoryBlock::CatalogClumpSize()
{
  return bswap32(this->__mdb.CatalogClumpSize);
}


uint16_t	MasterDirectoryBlock::rootdirFolders()
{
  return bswap16(this->__mdb.rootdirFolders);
}


uint32_t	MasterDirectoryBlock::fileCount()
{
  return bswap32(this->__mdb.fileCount);
}


uint32_t	MasterDirectoryBlock::folderCount()
{
  return bswap32(this->__mdb.folderCount);
}


uint32_t	MasterDirectoryBlock::overflowSize()
{
  return bswap32(this->__mdb.overflowSize);
}


uint16_t	MasterDirectoryBlock::embedSignature()
{
  return bswap16(this->__mdb.embedSignature);
}


bool		MasterDirectoryBlock::isWrapper()
{
  printf("%x\n", this->__mdb.embedSignature);
  return this->__mdb.embedSignature != HfsVolume;
}


uint16_t	MasterDirectoryBlock::embedStartBlock()
{
  return bswap16(this->__mdb.embedExtent.startBlock);
}


uint16_t	MasterDirectoryBlock::embedBlockCount()
{
  return bswap16(this->__mdb.embedExtent.blockCount);
}
