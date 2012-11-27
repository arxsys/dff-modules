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

MFTAttributeContent::MFTAttributeContent(MFTAttribute* mftAttribute) : Node("Unknown", (uint64_t)mftAttribute->contentSize(), NULL,  mftAttribute->ntfs())
{
  this->__mftAttribute = mftAttribute;
  this->__name = this->name();
}

MFTAttributeContent::~MFTAttributeContent()
{

}

void		MFTAttributeContent::fileMapping(FileMapping* fm)
{
//XXX Sparse ..
//XXX Compressed & Cypher ds MFTNode ou ici ?? 
//XXX pas ici Attribute ds plusieurs MFT ... et la c la merde ?
  if (this->__mftAttribute->isResident())
  {
     fm->push(0, this->__mftAttribute->contentSize(), this->__mftAttribute->mftEntryNode(), this->__mftAttribute->contentOffset());
  }
  else
  {
   return ;
// ds une fonction a part ??
// compressed size of run
//XXX spaaaarse offset = 0 ?
//XXX very fragment == run list trop long donc 2 attribut donc lire la xeme mft 
    uint64_t	runPreviousOffset = 0;
    int64_t	runOffset;
    uint64_t	runLength; //* ntfs->bootsectornode->clusterSize
    uint64_t	totalSize = 0;
    uint32_t	clusterSize = this->__mftAttribute->ntfs()->bootSectorNode()->clusterSize();
    Node*	fsNode = this->__mftAttribute->ntfs()->fsNode();
    RunListInfo	runListInfo;

    VFile* runList = this->__mftAttribute->mftEntryNode()->open();  
    if (runList->seek(this->__mftAttribute->offset() + this->__mftAttribute->runListOffset()) != (this->__mftAttribute->offset() + this->__mftAttribute->runListOffset()))
    {
      runList->close();
      return ;
    }

    while (totalSize < this->__mftAttribute->contentSize())
    { 
      runListInfo.byte = 0;
      runOffset = 0;
      runLength = 0;
  
      runList->read(&(runListInfo.byte), sizeof(uint8_t));
      runList->read(&runLength, runListInfo.info.lengthSize);
      runList->read(&runOffset, runListInfo.info.offsetSize);
 
      if ((int8_t)(runOffset >> 8 * (runListInfo.info.offsetSize-1)) < 0) 
      {
        int64_t toffset = -1;

        memcpy(&toffset, &runOffset, runListInfo.info.offsetSize);
        runOffset = toffset;
      }
   
      if (runLength == 0)
	break;
      // XXX test	
      
      runPreviousOffset += runOffset;
//XXX attention au dernier block a bien push pas la size d un cluster mais ce qu il faut pour pas push la slaaaaack a part si mfso le gere mais c mieux si c fait ici pour eviter les erreur 
      fm->push(totalSize, runLength * clusterSize, fsNode, runPreviousOffset * clusterSize);
      totalSize += runLength * clusterSize;  
    }
    runList->close();
//PARSE OTHER MFT YES IT'S MFT not datablock donc on se construit ds nous meme ? ca va marcher.. ? pleaseeeeeeeeeeeeeeeeeeeeeeeeeeeee 
 //   push firstVNC
  //  untill push last VNX
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

std::string	MFTAttributeContent::typeName(void)
{
  return (std::string("Unknown type"));
}
