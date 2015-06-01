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


#include "hfsprecords.hpp"


HfspCatalogEntry::HfspCatalogEntry() : __key(NULL), __data(NULL)
{
}


HfspCatalogEntry::~HfspCatalogEntry()
{
  if (this->__key != NULL)
    delete this->__key;
  if (this->__data != NULL)
    delete this->__data;
}


void		HfspCatalogEntry::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  CatalogEntry::process(origin, offset, size);
  this->__createContext();
  this->__key->process(origin, offset, this->keyDataLength());
  this->__data->process(origin, offset+this->dataOffset(), this->dataLength());
}


void		HfspCatalogEntry::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  CatalogEntry::process(buffer, size);
  this->__createContext();
  this->__key->process(buffer, this->keyDataLength());
  this->__data->process(buffer+this->dataOffset(), this->dataLength());
}


std::string	HfspCatalogEntry::name()
{
  std::string		ret;
  HfspCatalogThread*	thd;

  thd = NULL;
  if (this->type() == CatalogEntry::FolderRecord || this->type() == CatalogEntry::FileRecord)
    ret = this->__key->name();
  else if ((thd = dynamic_cast<HfspCatalogThread* >(this->__data)) != NULL)
    ret = thd->name();
  return ret;
}


uint32_t	HfspCatalogEntry::parentId()
{
  if (this->type() == CatalogEntry::FolderRecord || this->type() == CatalogEntry::FileRecord)
    return this->__key->parentId();
  else
    return this->__data->id();
}


uint32_t	HfspCatalogEntry::id()
{
  if (this->type() == CatalogEntry::FolderRecord || this->type() == CatalogEntry::FileRecord)
    return this->__data->id();
  else
    return this->__key->parentId();
}


CatalogKey*	HfspCatalogEntry::catalogKey()
{
  return this->__key;
}


CatalogData*	HfspCatalogEntry::catalogData()
{
  return this->__data;
}


Attributes	HfspCatalogEntry::attributes()
{
  Attributes	attrs;

  if (this->__data != NULL)
    attrs = this->__data->attributes();
  return attrs;
}


void		HfspCatalogEntry::__createContext() throw (std::string)
{
  if (this->__key == NULL)
    this->__key = new HfspCatalogKey();
  if (this->__data != NULL)
    {
      delete this->__data;
      this->__data = NULL;
    }
  if (this->type() == CatalogEntry::FileRecord)
    this->__data = new HfspCatalogFile();
  else if (this->type() == CatalogEntry::FolderRecord)
    this->__data = new HfspCatalogFolder();
  else if (this->type() == CatalogEntry::FileThread)
    this->__data = new HfspCatalogThread();
  else if (this->type() == CatalogEntry::FolderThread)
    this->__data = new HfspCatalogThread();
  else
    throw std::string("Wrong Hfsp Catalog Data type");
}


HfspCatalogKey::HfspCatalogKey()
{
}


HfspCatalogKey::~HfspCatalogKey()
{
}


void		HfspCatalogKey::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  CatalogKey::process(origin, offset, size);
  if ((this->_buffer != NULL) && (this->_size < sizeof(hfsp_catalog_key)))
    throw std::string("HfspCatalogKey : size is too small");
  memcpy(&this->__ckey, this->_buffer, sizeof(hfsp_catalog_key));  
}
 

void		HfspCatalogKey::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  CatalogKey::process(buffer, size);
  if ((this->_buffer != NULL) && (this->_size < sizeof(hfsp_catalog_key)))
    throw std::string("HfspCatalogKey : size is too small");
  memcpy(&this->__ckey, this->_buffer, sizeof(hfsp_catalog_key));
}


std::string	HfspCatalogKey::name()
{
  uint16_t	namelen;
  std::string	utf8;
  uint64_t	zero;
  

  namelen = bswap16(this->__ckey.unistrlen) * 2;
  zero = 0;
  if (((this->_buffer != NULL) && (this->_size >= namelen+8)))
    {
      utf8 = "";
      UnicodeString us((char*)(this->_buffer+8), namelen, "UTF-16BE");
      //XXX ugly but necessary condition to match HFS Private Data which starts with
      // 4 utf-16 null char...
      // https://developer.apple.com/legacy/library/technotes/tn/tn1150.html#HardLinks
      if (this->parentId() == 2 && namelen > 8 && memcmp(&zero, this->_buffer+8, 8) == 0)
	us.remove(0, 4);
      std::string ret = us.trim().toUTF8String(utf8);
    }
  return utf8;
}


uint32_t	HfspCatalogKey::parentId()
{
  return bswap32(this->__ckey.parentId);
}


HfspCatalogFile::HfspCatalogFile()
{
}


HfspCatalogFile::~HfspCatalogFile()
{
}


void		HfspCatalogFile::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  CatalogFile::process(origin, offset, size);
  if ((this->_buffer != NULL) && (this->_size < sizeof(hfsp_catalog_file)))
    throw std::string("HfspCatalogFile : size is too small");
  memcpy(&this->__cfile, this->_buffer, sizeof(hfsp_catalog_file));
}


void		HfspCatalogFile::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  CatalogFile::process(buffer, size);
  if ((this->_buffer != NULL) && (this->_size < sizeof(hfsp_catalog_file)))
    throw std::string("HfspCatalogFile : size is too small");
  memcpy(&this->__cfile, this->_buffer, sizeof(hfsp_catalog_file));
}


uint8_t		HfspCatalogFile::type()
{
  return CatalogEntry::FileRecord;
}


uint32_t	HfspCatalogFile::id()
{
  return bswap32(this->__cfile.id);
}


fork_data*	HfspCatalogFile::dataFork()
{
  fork_data*     fork;
  uint64_t	offset;
  
  
  if ((fork = (fork_data*)malloc(sizeof(fork_data))) == NULL)
    throw std::string("[HfspCatalogFile] Cannot alloc fork_data");
  else
    memcpy(fork, &this->__cfile.data, sizeof(fork_data));
  return fork;
}


ForkData*	HfspCatalogFile::resourceFork()
{
  // ForkData*     fork;
  // uint64_t	offset;

  // offset = this->_offset+offsetof(hfsp_catalog_file, resource);
  // fork = new ForkData(this->id(), this->_etree);
  // fork->process(this->_catalog, offset, ForkData::Resource);
  // return fork;
}


Attributes	HfspCatalogFile::attributes()
{
  Attributes		attrs;
  Attributes		aperms;
  HfsPermissions*	perms;

  attrs["created"] = new Variant(this->_timestampToVtime(this->__cfile.createDate));
  attrs["content modified"] = new Variant(this->_timestampToVtime(this->__cfile.contentModDate));
  attrs["attribute modified"] = new Variant(this->_timestampToVtime(this->__cfile.attributeModDate));
  attrs["accessed"] = new Variant(this->_timestampToVtime(this->__cfile.accessDate));
  attrs["backup"] = new Variant(this->_timestampToVtime(this->__cfile.backupDate));
  perms = new HfsPermissions();
  perms->process(this->__cfile.permissions);
  aperms = perms->attributes();
  attrs["Permissions"] = new Variant(aperms);
  delete perms;
  return attrs;
}


HfspCatalogFolder::HfspCatalogFolder()
{
}


HfspCatalogFolder::~HfspCatalogFolder()
{
}


void		HfspCatalogFolder::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  CatalogFolder::process(origin, offset, size);
  if ((this->_buffer != NULL) && (this->_size < sizeof(hfsp_catalog_folder)))
    throw std::string("HfsCatalogFolder : size is too small");
  memcpy(&this->__cfolder, this->_buffer, sizeof(hfsp_catalog_folder));
}


void		HfspCatalogFolder::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  CatalogFolder::process(buffer, size);
  if ((this->_buffer != NULL) && (this->_size < sizeof(hfsp_catalog_folder)))
    throw std::string("HfsCatalogFolder : size is too small");
  memcpy(&this->__cfolder, this->_buffer, sizeof(hfsp_catalog_folder));
}


uint8_t		HfspCatalogFolder::type()
{
  return CatalogEntry::FolderRecord;
}


uint32_t	HfspCatalogFolder::id()
{
  return bswap32(this->__cfolder.id);
}


Attributes	HfspCatalogFolder::attributes()
{
  Attributes		attrs;
  Attributes		aperms;
  HfsPermissions*	perms;

  attrs["created"] = new Variant(this->_timestampToVtime(this->__cfolder.createDate));
  attrs["content modified"] = new Variant(this->_timestampToVtime(this->__cfolder.contentModDate));
  attrs["attribute modified"] = new Variant(this->_timestampToVtime(this->__cfolder.attributeModDate));
  attrs["accessed"] = new Variant(this->_timestampToVtime(this->__cfolder.accessDate));
  attrs["backup"] = new Variant(this->_timestampToVtime(this->__cfolder.backupDate));
  perms = new HfsPermissions();
  perms->process(this->__cfolder.permissions);
  aperms = perms->attributes(); 
  attrs["Permissions"] = new Variant(aperms);
  delete perms;
  return attrs;
}


HfspCatalogThread::HfspCatalogThread()
{
}
 

HfspCatalogThread::~HfspCatalogThread()
{
}


void		HfspCatalogThread::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  CatalogThread::process(origin, offset, size);
}


void		HfspCatalogThread::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  CatalogThread::process(buffer, size);
}


uint8_t		HfspCatalogThread::type()
{
}


uint32_t	HfspCatalogThread::id()
{
}



std::string	HfspCatalogThread::name()
{
}


Attributes	HfspCatalogThread::attributes()
{
  Attributes	attrs;

  return attrs;
}
