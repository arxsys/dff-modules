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

#include "indexallocation.hpp"
#include "mftattributecontent.hpp"
#include "mftattribute.hpp"

#define PUSH_FLAGS(x, y)\
  if ((this->__fileName.flags & x) == x)\
    flagsList.push_back(NEW_VARIANT(std::string(y)));

IndexAllocation::IndexAllocation(MFTAttribute* mftAttribute) : MFTAttributeContent(mftAttribute)
{
  VFile* vfile = this->open();
  try 
  {
    for (uint64_t currentOffset = 0; currentOffset < this->size(); currentOffset += 4096)
    {
      if (vfile->seek(currentOffset) != currentOffset)
        break;

      IndexRecord indexRecord(vfile);
      if (indexRecord.signature() != *(uint32_t*)&"INDX")
        break;
      this->__indexRecords.push_back(indexRecord);

      //XXX code me
      //for entries in __indexRecords:
      //this->__entries.push_back(entries); 
    }
  }
  catch(const std::string& error)
  {
    std::cout << "$INDEX_ALLOCATION error : " << error << std::endl;
  }
  std::cout << "Record Max : " << this->size() / 4096 << std::endl;
  std::cout << "Record Found " << this->__indexRecords.size() << std::endl;
  delete vfile;
}

MFTAttributeContent*	IndexAllocation::create(MFTAttribute*	mftAttribute)
{
  return (new IndexAllocation(mftAttribute));
}

IndexAllocation::~IndexAllocation()
{
}

Attributes	IndexAllocation::_attributes(void)
{
  Attributes	attrs;

  MAP_ATTR("Attributes", MFTAttributeContent::_attributes())
  MAP_ATTR("Number of records", this->__indexRecords.size())

  //for reacord in this->
  //MAP_ATTR("signature", this->signature())
  //MAP_ATTR("fixup array offset", this->fixupArrayOffset())
  //MAP_ATTR("fixup array count", this->fixupArrayCount())
  //MAP_ATTR("sequence", this->sequence())
  //MAP_ATTR("VCN", this->vcn())

  return (attrs);
}

const std::string  IndexAllocation::typeName(void) const
{
  return (std::string("$NDEX_ALLOCATION"));
}

/* 
 *   IndexRecord 
 */

IndexRecord::IndexRecord(VFile *vfile)
{
  std::cout << "INDEX::allocation INDEX RECORD " << std::endl;
  if (vfile->read((void*)&this->__indexRecord, sizeof(IndexRecord_s)) != sizeof(IndexRecord_s))
    throw std::string("Can't read Index record");
  if (vfile->read((void*)&this->__indexList, sizeof(IndexList_s)) != sizeof(IndexList_s))
    throw std::string("Can't read Index record index list");

  vfile->seek(vfile->tell() - sizeof(IndexList_s));
  this->__indexEntries.readEntries(vfile, this->indexEntriesStart(), this->indexEntriesEnd());
}

uint32_t        IndexRecord::signature(void) const
{
  return (this->__indexRecord.signature);
}

uint16_t        IndexRecord::fixupArrayOffset(void) const
{
  return (this->__indexRecord.fixupArrayOffset);
}

uint16_t        IndexRecord::fixupArrayCount(void) const
{
  return (this->__indexRecord.fixupArrayCount);
}

uint64_t        IndexRecord::sequence(void) const
{
  return (this->__indexRecord.sequence);
}

uint64_t        IndexRecord::vcn(void) const
{
  return (this->__indexRecord.vcn);
}

/*
 *  IndexList_s 
 */

uint32_t        IndexRecord::indexEntriesStart(void) const
{
  return (this->__indexList.indexEntriesStart);
}

uint32_t        IndexRecord::indexEntriesEnd(void) const
{
  return (this->__indexList.indexEntriesEnd);
}

uint32_t        IndexRecord::endOfEntries(void) const
{
  return (this->__indexList.endOfEntries);
}

uint32_t        IndexRecord::flags(void) const
{
  return (this->__indexList.flags);
}

