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


#include "mftattributecontent.hpp"
#include "mftattribute.hpp"
#include "mftentrynode.hpp"
#include "ntfs.hpp"
#include "bootsector.hpp"

MFTAttributeContent::MFTAttributeContent(MFTAttribute* mftAttribute) : Node("MFTAC", (uint64_t)mftAttribute->contentSize(), NULL,  mftAttribute->ntfs()), __mftAttribute(mftAttribute)
{
  this->__mftAttribute->mftEntryNode()->updateState();
}

MFTAttributeContent::~MFTAttributeContent()
{
}

MFTAttribute* MFTAttributeContent::mftAttribute(void)
{
  return (this->__mftAttribute);
}

//default for $DATA -> DATA specialization ?
void		MFTAttributeContent::fileMapping(FileMapping* fm)
{
  if (this->__mftAttribute->isResident())
  {
     fm->push(0, this->__mftAttribute->contentSize(), this->__mftAttribute->mftEntryNode(), this->__mftAttribute->contentOffset());
  }
  else
  {
    // if fileMaping->startVCN ! et get size car contentSize et pas bon du coup :) 
    //fileMapping
    uint64_t	runPreviousOffset = 0;
    int64_t	runOffset;
    uint64_t	runLength;
    uint64_t	totalSize = this->__mftAttribute->VNCStart() * 512;
    uint32_t	clusterSize = this->__mftAttribute->ntfs()->bootSectorNode()->clusterSize();
    Node*	fsNode = this->__mftAttribute->ntfs()->fsNode();
    RunListInfo	runListInfo;

    VFile* runList = this->__mftAttribute->mftEntryNode()->open();  
   
    if (runList->seek(this->__mftAttribute->offset() + this->__mftAttribute->runListOffset()) != (this->__mftAttribute->offset() + this->__mftAttribute->runListOffset()))
    {
      delete runList;
      return ;
    }

    //XXX because no size in second $DATA -> get it or find an other way to exit or if contentSize == 0 else
    while (true) //totalSize < this->__mftAttribute->contentSize()) //XXX multi data !
    { 
      runListInfo.byte = 0;
      runOffset = 0;
      runLength = 0;

      if (runList->read(&(runListInfo.byte), sizeof(uint8_t)) != sizeof(uint8_t))
        break;

      if (runListInfo.info.offsetSize > 8) 
        break;
     
      if (runList->read(&runLength, runListInfo.info.lengthSize) != runListInfo.info.lengthSize)
        break;

      if (runListInfo.info.offsetSize)
        if (runList->read(&runOffset, runListInfo.info.offsetSize) != runListInfo.info.offsetSize)
           break;

      if ((int8_t)(runOffset >> (8 * (runListInfo.info.offsetSize - 1))) < 0) 
      {
        int64_t toffset = -1;

        memcpy(&toffset, &runOffset, runListInfo.info.offsetSize);
        runOffset = toffset;
      }
 
      if (runLength == 0)
	break;
      runPreviousOffset += runOffset;

      if (runOffset == 0) //Sparse || runOffset == -1) ?? pas possible car on rad pas donc check offsetSize plutot ?
        fm->push(totalSize, runLength * clusterSize, NULL, 0);
      else 
        fm->push(totalSize, runLength * clusterSize, fsNode, runPreviousOffset * clusterSize);
      totalSize += runLength * clusterSize;  
    }
    delete runList;
  }
}

uint8_t*	MFTAttributeContent::data(void)
{
/*  if (this->__mftAttribute->isResident())
  {
     this->__mftAttribute->ntfs->vfile->read bla bla bla
  }
  else
    throw std::string("Can't use data on this mft attribute content");*/
  return NULL;
}

Attributes	MFTAttributeContent::_attributes(void)
{
  Attributes	attrs;

  return attrs;
}

//There could be multiple content of same id they must have diferent name because DFF::Attributes are a map otherwise map entry would be overwirtten
std::string	MFTAttributeContent::attributeName(void)
{
 if (this->__mftAttribute->nameLength())
    return (std::string("attribute name found in self"));
  return (this->typeName());
}

const std::string	MFTAttributeContent::typeName(void) const
{
  std::ostringstream  idStream;

  if (this->__mftAttribute)
    idStream << "Unknown MFT attribute (" << this->__mftAttribute->typeID() << ")";

  return (idStream.str());
}
