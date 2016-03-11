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

#include <archive.h>
#include <archive_entry.h>

#include "exceptions.hpp"
#include "fdmanager.hpp"
#include "node.hpp"
#include "vfile.hpp"

#include "decompressor.hpp"
#include "decompressornode.hpp"

using namespace DFF;

DecompressorFdinfo::DecompressorFdinfo() : arch(NULL), archiveReadOffset(0), buffer(NULL), bufferSize(0), bufferOffset(0)
{

}

ArchiveData::ArchiveData(Node* parent) : node(parent), vfile(NULL), buffer(malloc(ArchiveDataBufferSize))
{
}

ArchiveData::~ArchiveData() //called ?
{
  free(buffer);
}

Decompressor::Decompressor() : fso("uncompress"), __rootNode(NULL), __fdManager(new FdManager)
{
}

Decompressor::~Decompressor()
{
  if (this->__fdManager)
   delete this->__fdManager;
}

archive*   Decompressor::newArchive(void)
{
  struct archive *archiv = archive_read_new();
  archive_read_support_format_all(archiv);
  archive_read_support_filter_all(archiv);

  ArchiveData* data = new ArchiveData(this->__rootNode);
  archive_read_set_open_callback(archiv, &this->archiveOpen);
  archive_read_set_read_callback(archiv, &this->archiveRead);
  archive_read_set_seek_callback(archiv, &this->archiveSeek);
  archive_read_set_close_callback(archiv,  &this->archiveClose);
  archive_read_set_callback_data(archiv, (void*)data);
  
  return (archiv);
}

void    Decompressor::createNodeTree(archive* archiv)
{
  // Create Tree if archive or subnode if only compressed
  int res = archive_read_open1(archiv); 
  if (res != ARCHIVE_OK)
    throw envError("Can't open archive");

  struct archive_entry *entry;

  //std::cout << "creating entry for " << this->rootNode()->absolute() << std::endl;
  Node* decompressorNode = new Node("Uncompressed", 0, NULL, this);
  while (archive_read_next_header(archiv, &entry) == ARCHIVE_OK) 
  {
    uint64_t    size = archive_entry_size(entry);
    std::string fullPath = archive_entry_pathname(entry);
    //std::cout << "  " << fullPath << std::endl;
    std::string consumedPath = fullPath;
    Node* parentChunk = decompressorNode;
    while (consumedPath != "")
    {
       std::string pathChunk = consumedPath.substr(0, consumedPath.find("/"));
       size_t res = consumedPath.find("/");
       if (res + 1 == consumedPath.size() || res == std::string::npos)
         consumedPath = "";
       else
         consumedPath = consumedPath.substr(res + 1);

       if (consumedPath == "" && size)
       {
         new DecompressorNode(pathChunk, size, parentChunk, this);
         break;
       }

       std::vector<Node*> children = parentChunk->children();
       std::vector<Node*>::const_iterator child = children.begin();
       for (; child != children.end(); ++child)
       {
          if (pathChunk == (*child)->name())
          {
            parentChunk = (*child);
            break;
          }
       }
       if (child == children.end())
         parentChunk = new Node(pathChunk, 0, parentChunk, this);
    }
    archive_read_data_skip(archiv);
  }
  res = archive_read_free(archiv);
  if (res != ARCHIVE_OK)
    throw envError("Can't free archive");

  //if at least one entry was created (module can fail)
  this->registerTree(this->__rootNode, decompressorNode);

}

void    Decompressor::start(Attributes args)
{
  if (args.find("file") != args.end())
    this->__rootNode = args["file"]->value<Node* >();
  else
    throw envError("Registry module need a file argument.");

  /** 
   *   Crate Archive structure & setcallback
   */

  archive* archiv = this->newArchive();
  this->createNodeTree(archiv);

  this->setStateInfo("Finished successfully");
  this->res["Result"] = Variant_p(new Variant(std::string("Decompressor finished successfully.")));
}

Node*		Decompressor::rootNode(void) const
{
  return (this->__rootNode);
}

void            Decompressor::setStateInfo(const std::string& str)
{
  this->stateinfo = str;
}

/**
 *  Archive callback to read on DFF VFile
 */

int             Decompressor::archiveOpen(struct archive *, void *data)
{

  ArchiveData* archiveData = (ArchiveData*)data;

  archiveData->vfile = archiveData->node->open();
  if (archiveData->vfile == NULL)
    return (-1);
  return (0);
}

ssize_t         Decompressor::archiveRead(struct archive *, void *data, const void **buffer)
{
  ArchiveData* archiveData = (ArchiveData*)data;

  int64_t res = archiveData->vfile->read(archiveData->buffer, ArchiveDataBufferSize); //return less if block size < 4096 ?
  *buffer = archiveData->buffer;
  return (res);
}

int64_t         Decompressor::archiveSeek(struct archive *, void *data, int64_t offset, int whence)
{
  return (((ArchiveData*)data)->vfile->seek((uint64_t)offset, (int32_t)whence));
}

int             Decompressor::archiveClose(struct archive *, void *data)
{
  ((ArchiveData*)data)->vfile->close();
  return (0);
}

archive*        Decompressor::openNodeArchive(Node* node)
{
  std::cout << "Recreating archive for node " << node->absolute() << std::endl;
  archive* archiv = this->newArchive();
  //check error or throw 
  std::string absolute = node->absolute();
  std::string archivPath = absolute.substr(absolute.rfind("Uncompressed/") + 13);

  int res = archive_read_open1(archiv); 
  if (res != ARCHIVE_OK)
    throw envError("Can't open archive");

  //chcek error or throw 
  struct archive_entry *entry;
  int flag = 0;
  while (archive_read_next_header(archiv, &entry) == ARCHIVE_OK) 
  {
    if (archive_entry_pathname(entry) == archivPath)
    {
      flag = 1;
      break; 
    }
  }
  if (flag == 0)
    throw std::string("Can't find file in archive");
  
  return (archiv);
}

/**
 *   DFF VFile method to return uncompressed content
 */
int32_t         Decompressor::vopen(Node* node)
{
  DecompressorFdinfo* fi = new DecompressorFdinfo();
  fi->node = node;
  fi->offset = 0;
  //fi->buffer = new uint8_t[DecompressorFdinfoBufferSize]; //if too big will read a lot for nothing on some file (like when we scan for exemple 8192)
  fi->arch = this->openNodeArchive(fi->node);

  return (this->__fdManager->push(fi));
}

int32_t         Decompressor::vread(int32_t fd, void *rbuff, uint32_t size)
{
  try
  {
    /*USE large buffering at least 1MO to avoid little backward seek 
     check if seek is after so no need to recreate openNodearchive 
     if seek is in our buffer (get some room before and after so it's morre efficent in our buffer
     if need to read preempt data if seek look at our buffer et c... read is not so long reopening very long (it must be avoid at most cost )
     and seek is long on large files 
    */
    DecompressorFdinfo* fi = (DecompressorFdinfo*)this->__fdManager->get(fd);
    if (fi->offset >= fi->node->size())
      return 0;

    if (fi->offset < fi->archiveReadOffset)
    {
      archive_read_free(fi->arch);
      fi->arch = this->openNodeArchive(fi->node);
      fi->archiveReadOffset = 0;
    }

    int32_t  currentSize = 0;
    char skipBuff[1024*1024];
    while (fi->archiveReadOffset < fi->offset)
    {
      if (fi->offset - fi->archiveReadOffset > 1024*1024)
        currentSize = 1024*1024;
      else
        currentSize = fi->offset - fi->archiveReadOffset;
      int32_t res = archive_read_data(fi->arch, skipBuff, currentSize); //use zero copy skip will be great here
      fi->archiveReadOffset += res;
    }

    int32_t res = archive_read_data(fi->arch, rbuff, size);
    fi->offset += res;
    fi->archiveReadOffset += res;

    return (res);
  }
  catch (...) 
  {
   std::cout << "vread catch error " << std::endl;
    return (0);
  }
  //get archive & entry data
  //call decompression lib on this node and return res 
  return (0);
}

uint64_t        Decompressor::vseek(int32_t fd, uint64_t offset, int32_t whence)
{
  Node*	node;
  fdinfo* fi;

  try
  {
    fi = this->__fdManager->get(fd);
    node = fi->node;

    if (whence == 0)
    {
      if (offset <= node->size())
      {
        fi->offset = offset;
        return (fi->offset);
      } 
    }
    else if (whence == 1)
    {
      if (fi->offset + offset <= node->size())
      {
        fi->offset += offset;
	return (fi->offset);
      }
    }
    else if (whence == 2)
    {
      fi->offset = node->size();
      return (fi->offset);
    }
  }
  catch (...)
  {
    return ((uint64_t) -1);
  }

  return ((uint64_t) -1);
}

uint64_t        Decompressor::vtell(int32_t fd)
{
  try 
  {
    fdinfo* fi = this->__fdManager->get(fd);
    return (fi->offset);
  }
  catch (...)
  {
    return ((uint64_t)-1);
  }
}

int32_t         Decompressor::vclose(int32_t fd)
{
  DecompressorFdinfo* fi = (DecompressorFdinfo*)(this->__fdManager->get(fd));

  archive_read_free(fi->arch);
  //delete[] fi->buffer;

  this->__fdManager->remove(fd);
  return (0);
}

uint32_t        Decompressor::status(void)
{
  return (0);
}

int32_t         Decompressor::vwrite(int fd, void* buff, unsigned int size)
{
  return (0);
}
