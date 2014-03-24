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

CompressionInfo::CompressionInfo(uint64_t runSize)
{
  this->uncomp_buf = (char*)malloc(runSize);
  this->comp_buf = (char*)malloc(runSize);
  memset(this->uncomp_buf, 0, runSize);
  memset(this->comp_buf, 0, runSize);
  this->buf_size_b = runSize; //XXX bs
  this->uncomp_idx = 0;
  this->comp_len = 0;
}

CompressionInfo::~CompressionInfo(void)
{
  free(this->uncomp_buf);
  free(this->comp_buf);
}

void MFTAttributeContent::uncompressUnit(CompressionInfo* comp)
{
  comp->uncomp_idx = 0;
  for (size_t cl_index = 0; cl_index + 1 < comp->comp_len;) 
  {
    size_t blk_end;         // index into the buffer to where block ends
    size_t blk_size;        // size of the current block
    uint8_t iscomp;         // set to 1 if block is compressed
    size_t blk_st_uncomp;   // index into uncompressed buffer where block started

    blk_size = ((((unsigned char) comp->comp_buf[cl_index + 1] << 8) | ((unsigned char) comp->comp_buf[cl_index])) & 0x0FFF) + 3;
    if (blk_size == 3)
      break;

    blk_end = cl_index + blk_size;
    if (blk_end > comp->comp_len) 
      throw std::string("Block length longer than buffer length");
    
    if ((comp->comp_buf[cl_index + 1] & 0x8000) == 0)
      iscomp = 0;
    else
      iscomp = 1;

    blk_st_uncomp = comp->uncomp_idx;
    cl_index += 2;
    if ((iscomp) || (blk_size - 2 != 4096)) 
    {
      while (cl_index < blk_end) 
      {
        unsigned char header = comp->comp_buf[cl_index];
        cl_index++;
        for (int a = 0; a < 8 && cl_index < blk_end; a++) 
        {
          if ((header & NTFS_TOKEN_MASK) == NTFS_SYMBOL_TOKEN) 
          {
            if (comp->uncomp_idx >= comp->buf_size_b) 
              throw ("Trying to write past end of uncompression buffer");
            comp->uncomp_buf[comp->uncomp_idx++] = comp->comp_buf[cl_index];
            cl_index++;
          }
          else 
          {
            size_t i;
            int shift;
            size_t start_position_index = 0;
            size_t end_position_index = 0;
            unsigned int offset = 0;
            unsigned int length = 0;
            uint16_t pheader;

            if (cl_index + 1 >= blk_end) 
              throw("Phrase token index is past end of block:");

            pheader = ((((comp->comp_buf[cl_index +1]) << 8) & 0xFF00) | (comp->comp_buf[cl_index] & 0xFF));
            cl_index += 2;
            shift = 0;
            for (i = comp->uncomp_idx - blk_st_uncomp - 1; i >= 0x10; i >>= 1) 
            {
              shift++;
            }

            offset = (pheader >> (12 - shift)) + 1;
            length = (pheader & (0xFFF >> shift)) + 2;
            start_position_index = comp->uncomp_idx - offset;
            end_position_index = start_position_index + length;
            if (offset > comp->uncomp_idx) 
              throw std::string("Phrase token offset is too large:");
            else if (length + start_position_index > comp->buf_size_b) 
              throw std::string("Phrase token length is too large");
            else if (end_position_index - start_position_index + 1 > comp->buf_size_b - comp->uncomp_idx) 
              throw std::string("Phrase token length is too large for rest of uncomp buf");

            for (; start_position_index <= end_position_index && comp->uncomp_idx < comp->buf_size_b; start_position_index++) 
              comp->uncomp_buf[comp->uncomp_idx++] = comp->uncomp_buf[start_position_index];
          }
          header >>= 1;
        }
     }
   }
    else 
    {
      while (cl_index < blk_end && cl_index < comp->comp_len) 
      {
        if (comp->uncomp_idx >= comp->buf_size_b) 
          throw("Trying to write past end of uncompression buffer (1) -- corrupt data?)");
        comp->uncomp_buf[comp->uncomp_idx++] = comp->comp_buf[cl_index++];
      }
    }
  }
}

uint64_t MFTAttributeContent::uncompressBlock(VFile* fs, RunList run, char** data, CompressionInfo* comp, uint64_t* lastValidOffset)
{
  uint32_t clusterSize = this->__mftAttribute->ntfs()->bootSectorNode()->clusterSize();
  uint64_t blockSize = clusterSize * 16;
  uint64_t runLength = run.length; 
  uint64_t runOffset = run.offset;
  uint64_t total = 0;

  if (run.length > 16)
    *data = (char*)malloc(clusterSize * ((runLength / 16) + 1) * 16);
  else
    *data = (char*)malloc(blockSize);
   
  if (runLength >= 16) //not compressed
  {
    comp->uncomp_idx = 0;
    if (runOffset == 0)
    {
      memset(*data, 0, ((runLength / 16) * 16) * clusterSize);
      total += ((run.length / 16) * 16) * clusterSize;
      return (total); //even if there is still data a compressed run will follow
    }
    else
    {
      fs->seek(runOffset * clusterSize);
      fs->read(*data, ((runLength / 16) * 16) * clusterSize);
      runOffset += (runLength / 16) * 16;
      comp->uncomp_idx += clusterSize * ((run.length / 16) * 16);
      *lastValidOffset = runOffset;
    }
    total += ((run.length / 16) * 16) * clusterSize;
    runLength = runLength % 16;
    if (runLength == 0)
      return total;
  }
  if (runOffset && runLength < 16)
  {
    if (fs->seek(runOffset * clusterSize) != (runOffset * clusterSize))
      throw std::string("Can't seek to data on fs node");
    if (fs->read(&(comp->comp_buf[comp->comp_len]), clusterSize * runLength) != clusterSize * runLength)
      throw std::string("Can't read data on fs node");
    comp->comp_len += clusterSize * runLength; //increment buffer size
    *lastValidOffset += runLength;
    
    this->uncompressUnit(comp);

    if (run.length > 16)
      memcpy(*data + ((run.length / 16) * 16) * clusterSize, comp->uncomp_buf, blockSize);
    else
      memcpy(*data, comp->uncomp_buf, blockSize);
    total += blockSize;
    return (total);
  }
  return (total);
}

uint64_t        MFTAttributeContent::uncompress(uint64_t offset, uint8_t* buff, uint64_t size)
{
  if (this->__mftAttribute->compressionUnitSize() == 0 && this->__mftAttribute->VNCStart() == 0)
    return (0);
  
  if (this->__mftAttribute->compressionUnitSize() == 0)
  {
   //pass block size as arg ? comme ca on a le premier c bon 
    //fstream.seekp(this->__mftAttribute->VNCStart() * 512);
  }
  uint64_t lastValidOffset = 0;
  uint32_t clusterSize = this->__mftAttribute->ntfs()->bootSectorNode()->clusterSize();
  std::vector<RunList>  runList = this->runList(); //runList
  std::vector<RunList>::iterator run = runList.begin(); 
  VFile* fs = this->__mftAttribute->ntfs()->fsNode()->open();
  uint64_t readed = 0;
  uint64_t totalRead = 0;
  uint64_t startOffset = this->__mftAttribute->VNCStart() * clusterSize;

  for (; (readed < size) && (run != runList.end()); run++)
  {
    char* data = NULL;
    try
    {
      int64_t runSize = (*run).length;
      if (runSize < 16)
        runSize = 16 * clusterSize;
      else
        runSize = runSize * clusterSize;
      CompressionInfo comp(runSize);

      if ((*run).offset != 0)
        lastValidOffset = (*run).offset; //keep track of last offset
      
      //if (offset >= (*run).offset) //presque ca :) sauf que runOffset et relative au debut de la mft / pffset du fs mois je veux le totalOffset de chque run read d aboord :)
      uint64_t dataSize = this->uncompressBlock(fs, *run, &data, &comp, &lastValidOffset);
      if (dataSize == 0) //sparse for end of compression block
      {
        free(data);
        continue;
      }
      uint64_t currentOffset = totalRead + startOffset;
      uint64_t nextOffset = offset + readed;
      uint64_t maxOffset = totalRead  + startOffset +dataSize;
      if ((currentOffset <= nextOffset) && (nextOffset <= maxOffset)) //in range 
      {
        //copy data of range 
        if (dataSize <= 0)
        {
          free(data);
          delete fs;
          return (readed);
        }
        uint64_t dataOff = nextOffset - currentOffset;
        uint64_t toRead = size - readed;
        uint64_t readMax = maxOffset - nextOffset;
        if (toRead > readMax)
          toRead = readMax;
        if (!toRead)
        {
          free(data);
          totalRead += dataSize;
          continue ; //block boundary 
        }
        if (readed + dataSize > size)
        {
          memcpy(buff + readed, data + dataOff, toRead);
          free(data);
          delete fs;
          return (toRead);
        }
        memcpy(buff + readed, data + dataOff, dataSize - dataOff);
        readed += dataSize - dataOff;
      }
      free(data); 
      totalRead += dataSize;
    }
    catch(std::string const& error)
    {
      free(data); 
      std::cout << "NTFS uncompression error : " << error << std::endl;
      break;
    } 
    //totalSize += (*run).length * clusterSize;  
  }
  delete fs;
  return readed;
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
    uint32_t	clusterSize = this->__mftAttribute->ntfs()->bootSectorNode()->clusterSize();
    uint64_t	totalSize = this->__mftAttribute->VNCStart() * clusterSize;
    Node*	fsNode = this->__mftAttribute->ntfs()->fsNode();
    std::vector<RunList> runList = this->runList();
    std::vector<RunList>::iterator run = runList.begin();

    for (; run != runList.end(); ++run)
    {
      if ((*run).offset == 0) //Sparse || runOffset == -1 
        fm->push(totalSize, (*run).length * clusterSize, NULL, 0);
      else 
        fm->push(totalSize, (*run).length * clusterSize, fsNode, (*run).offset * clusterSize);
                                                            //check push slack %clustersize
      totalSize += (*run).length * clusterSize;  
    }
  }
}

std::vector<RunList>    MFTAttributeContent::runList(void)
{
  std::vector<RunList>   runLists;

  uint64_t	runPreviousOffset = 0;
  int64_t	runOffset;
  uint64_t	runLength;

  VFile* runList = this->__mftAttribute->mftEntryNode()->open();  
   
  if (runList->seek(this->__mftAttribute->offset() + this->__mftAttribute->runListOffset()) != (this->__mftAttribute->offset() + this->__mftAttribute->runListOffset()))
  {
    delete runList;
    return (runLists);
  }

  while (true) //totalSize < this->__mftAttribute->contentSize()) //XXX multi data !
  { 
    RunListInfo	runListInfo;
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

    RunList run;
    if (runOffset == 0)
      run.offset = 0;
    else 
      run.offset = runPreviousOffset;
    run.length = runLength;
    runLists.push_back(run);
  }
  delete runList;
  return (runLists);
}


/*
 *  Return MFTAttribute attributes
 */ 
Attributes	MFTAttributeContent::_attributes(void)
{
  Attributes	attrs;

  if (this->__mftAttribute == NULL)
    return attrs;

  MAP_ATTR("type id", this->__mftAttribute->typeId())
  MAP_ATTR("length", this->__mftAttribute->length())
  if (this->__mftAttribute->nameSize())
    MAP_ATTR("name", this->attributeName())
  MAP_ATTR("flags", this->__mftAttribute->flags()) //XXX
  MAP_ATTR("id", this->__mftAttribute->id())
  if (this->__mftAttribute->isResident())
  {
    MAP_ATTR("Content size", this->__mftAttribute->contentSize());
    MAP_ATTR("Content offset", this->__mftAttribute->contentOffset());
  }
  else
  {
    MAP_ATTR("VNC start", this->__mftAttribute->VNCStart())
    MAP_ATTR("VNC end", this->__mftAttribute->VNCEnd())
    MAP_ATTR("Run list offset", this->__mftAttribute->runListOffset())
    MAP_ATTR("Compression unit size", this->__mftAttribute->compressionUnitSize())
    MAP_ATTR("Content allocated size", this->__mftAttribute->contentAllocatedSize())
    MAP_ATTR("Content actual size", this->__mftAttribute->contentActualSize())
    MAP_ATTR("Content initialized size", this->__mftAttribute->contentInitializedSize())
  }

  return attrs;
}

std::string	MFTAttributeContent::attributeName(void) const
{
  if (this->__mftAttribute->nameSize())
    return (this->__mftAttribute->name());
  return ("");
}

const std::string	MFTAttributeContent::typeName(void) const
{
  std::ostringstream  idStream;

  if (this->__mftAttribute)
    idStream << "Unknown MFT attribute (" << this->__mftAttribute->typeId() << ")";

  return (idStream.str());
}
