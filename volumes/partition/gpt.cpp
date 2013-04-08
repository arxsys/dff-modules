/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
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

#include "gpt.hpp"
#include "gpttypes.hpp"

GptPartition::GptPartition()
{
  this->__vfile = NULL;
  this->__origin = NULL;
  this->__hidden = 0;
}

GptPartition::~GptPartition()
{
}

bool	GptPartition::process(Node* origin, uint64_t offset, uint32_t sectsize) throw (vfsError)
{
  this->__origin = origin;
  this->__offset = offset;
  this->__sectsize = sectsize;
  this->__vfile = this->__origin->open();
  this->__readHeader();
  return true;
}


void		GptPartition::makeNodes(Node* root, fso* fsobj)
{
  std::map<uint64_t, gpt_meta*>::iterator	alloc;
  std::map<uint64_t, uint64_t>::iterator	unalloc;
  std::stringstream				ostr;
  std::string					name;
  PartitionNode*				pnode;
  Node*						root_unalloc;
  uint32_t					count;

  this->__makeUnallocated();
  count = 0;
  for (alloc = this->__allocated.begin(); alloc != this->__allocated.end(); ++alloc)
    {
      if (alloc->second->entry->name().empty())
	ostr << "NONAME " << ++count;
      else
	ostr << alloc->second->entry->name();
      pnode = new PartitionNode(ostr.str(), alloc->second->entry->size() * this->__sectsize, root, fsobj);
      pnode->setCtx(this, alloc->first, PRIMARY);
      ostr.str("");
    }
  if (this->__unallocated.size() > 0 && ((root_unalloc = new Node("Unallocated", 0, root, fsobj)) != NULL))
    {
      for (unalloc = this->__unallocated.begin(); unalloc != this->__unallocated.end(); ++unalloc)
	{
	  ostr << unalloc->first << "s--" << unalloc->second - 1 << "s";
	  pnode = new PartitionNode(ostr.str(), (unalloc->second - unalloc->first) * this->__sectsize, root_unalloc, fsobj);
	  pnode->setCtx(this, unalloc->first, UNALLOCATED);
	  ostr.str("");
	}
    }
}


Attributes	GptPartition::result()
{
  std::map<uint64_t, gpt_meta*>::iterator	alloc;
  std::map<uint64_t, uint64_t>::iterator	unalloc;
  std::stringstream	ostr;
  Attributes		allocres;
  Attributes		unallocres;
  Attributes		res;
  uint32_t		count;
  
  for (alloc = this->__allocated.begin(); alloc != this->__allocated.end(); ++alloc)
    {
      ostr.str("");
      ostr << "Partition " << alloc->second->epos;
      allocres[ostr.str()] = new Variant(this->entryAttributes(alloc->first, PRIMARY));
    }
  count = 1;
  for (unalloc = this->__unallocated.begin(); unalloc != this->__unallocated.end(); ++unalloc)
    {
      ostr.str("");
      ostr << "Unallocated " << count;
      unallocres[ostr.str()] = new Variant(this->entryAttributes(unalloc->first, UNALLOCATED));
      count++;
    }
  if (allocres.size())
    res["Regular"] = new Variant(allocres);
  if (unallocres.size())
    res["Unallocated"] = new Variant(unallocres);
  return res;
}


Attributes	GptPartition::entryAttributes(uint64_t entry, uint8_t type)
{
  std::map<uint64_t, gpt_meta*>::iterator	alloc;
  std::map<uint64_t, uint64_t>::iterator	unalloc;
  std::stringstream	ostr;
  Attributes		vmap;

  if ((type == UNALLOCATED) && ((unalloc = this->__unallocated.find(entry)) != this->__unallocated.end()))
    {
      vmap["starting lba"] = new Variant(unalloc->first);
      vmap["ending lba"] = new Variant(unalloc->second);
      vmap["total lba"] = new Variant(unalloc->second - unalloc->first + 1);
    }
  else if ((type != UNALLOCATED) && ((alloc = this->__allocated.find(entry)) != this->__allocated.end()))
    {
      vmap["starting lba"] = new Variant(alloc->second->entry->firstLba());
      vmap["ending lba"] = new Variant(alloc->second->entry->lastLba());
      vmap["total lba"] = new Variant(alloc->second->entry->size());
      vmap["entries meta offset"] = new Variant(alloc->second->eoffset);
      vmap["position in entries table"] = new Variant(alloc->second->epos);
      vmap["name"] = new Variant(alloc->second->entry->name());
      vmap["type guid"] = new Variant(alloc->second->entry->typeGuid());
      vmap["partition type"] = new Variant(this->__guidMapping(alloc->second->entry->typeGuid()));
      vmap["partition guid"] = new Variant(alloc->second->entry->partGuid());
    }
  return vmap;
}


void		GptPartition::mapping(FileMapping* fm, uint64_t entry, uint8_t type)
{
  std::map<uint64_t, gpt_meta*>::iterator	alloc;
  std::map<uint64_t, uint64_t>::iterator	unalloc;  
  uint64_t	offset;
  uint64_t	size;
  uint64_t	tsize;
  bool		process;

  process = false;
  if ((type == UNALLOCATED) && ((unalloc = this->__unallocated.find(entry)) != this->__unallocated.end()))
    {
      offset = unalloc->first * this->__sectsize;
      size = (unalloc->second - unalloc->first + 1) * this->__sectsize;
      process = true;
    }
  else if ((type != UNALLOCATED) && ((alloc = this->__allocated.find(entry)) != this->__allocated.end()))
    {
      offset = alloc->second->entry->firstLba() * this->__sectsize;
      size = alloc->second->entry->size() * this->__sectsize;
      process = true;
    }
  if (process)
    {
      //XXX NEED CASE DUMP
      if (offset > this->__origin->size())
	fm->push(0, size);
      //XXX NEED CASE DUMP
      else if (offset + size > this->__origin->size())
	{
	  tsize = this->__origin->size() - offset;
	  fm->push(0, tsize, this->__origin, offset);
	  fm->push(tsize, tsize - size);
	}
      else
	fm->push(0, size, this->__origin, offset);
    }
}


uint32_t	GptPartition::entriesCount()
{
  return this->__allocated.size();
}

uint64_t	GptPartition::lba(uint32_t which)
{
  std::map<uint64_t, gpt_meta*>::iterator	mit;
  uint32_t		count;
  
  mit = this->__allocated.begin();
  if (which < this->__allocated.size())
    {
      count = 0;
      while (count != which)
	mit++;
      return mit->second->entry->firstLba();
    }
  else
    return (uint64_t)-1;
}


void	GptPartition::__readHeader() throw (vfsError)
{
  Attributes	hattrs;

  this->__vfile->seek(this->__offset + this->__sectsize);
  if (this->__vfile->read(&this->__header, sizeof(gpt_header)) == sizeof(gpt_header))
    {
      // Hmm, there's something wrong but other fields could
      // be ok. Just warn user but let's continue processing
      if (this->__header.lastUsableLba() < this->__header.firstUsableLba())
	;
      this->__readEntries();
    }
  // CHECK if current lba is really needed and how
  // sanitize & check if last_lba possible
  //                  backup_lba is possible
  //this->__readEntries(entries_lba, entries_count, entry_size); 
}

void	GptPartition::__readEntries() throw (vfsError)
{
  uint32_t	ecount;
  uint32_t	entries_count;
  uint32_t	entry_size;
  int32_t	rsize;
  gpt_entry	entry;
  gpt_meta*	meta;
  uint64_t	offset;
  
  entries_count = this->__header.entriesCount();
  entry_size = this->__header.entrySize();
  offset = this->__vfile->seek(this->__header.entriesLba()*this->__sectsize);
  std::cout << "guid: " << this->__header.diskGuid() << std::endl;
  if (entry_size > sizeof(gpt_entry))
    rsize = sizeof(gpt_entry);
  else
    rsize = entry_size;
  for (ecount = 0; ecount != entries_count; ++ecount)
    {
      if ((this->__vfile->read(&entry, rsize) == rsize)
	  && (entry.firstLba() > 0 && entry.firstLba() < entry.lastLba()))
	{
	  meta = new gpt_meta;
	  meta->entry = new gpt_entry;
	  meta->epos = ecount;
	  meta->eoffset = offset;
	  memcpy(meta->entry, &entry, rsize);
	  this->__allocated[entry.firstLba()] = meta;
	}
      offset += entry_size;
      this->__vfile->seek(offset);
    }
}


void		GptPartition::__makeUnallocated()
{
  std::map<uint64_t, gpt_meta*>::iterator	mit;
  uint64_t					first_lba;

  first_lba = 0;
  for (mit = this->__allocated.begin(); mit != this->__allocated.end(); ++mit)
    {
      if (mit->second->entry->firstLba() > first_lba)
	this->__unallocated[first_lba] = mit->second->entry->firstLba() - 1;
      first_lba = mit->second->entry->lastLba() + 1;
    }
  if ((this->__offset + (first_lba * this->__sectsize)) < this->__origin->size())
    this->__unallocated[first_lba] = (this->__origin->size() / this->__sectsize) - 1;
}


std::string	GptPartition::__guidMapping(std::string guid)
{
  std::string	res;
  int		i;
  
  i = 0;
  res = "Unknown";
  while (*(guid_map[i].guid) != '\0')
    {
      if (guid == guid_map[i].guid)
	{
	  res = guid_map[i].fstype;
	  break;
	}
      i++;
    }
  return res;
}
