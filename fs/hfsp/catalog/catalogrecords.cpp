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

#include "catalogrecords.hpp"
#include <unicode/unistr.h>


CatalogKey::CatalogKey()
{
}

CatalogKey::~CatalogKey()
{
}


void		CatalogKey::process(Node* origin, uint64_t offset, uint16_t size) throw (std::string)
{
  uint8_t*	key;

  KeyedRecord::process(origin, offset, size);
  key = NULL;
  if (((key = this->key()) != NULL) && (this->keyDataLength() >= sizeof(catalog_key)))
    memcpy(&this->__ckey, key, sizeof(catalog_key));
  if (key != NULL)
    free(key);
}


uint32_t	CatalogKey::parentId()
{
  return bswap32(this->__ckey.parentId);
}


uint16_t	CatalogKey::nameDataLength()
{
  return this->nameLength()*2;
}


uint16_t	CatalogKey::nameLength()
{
  return bswap16(this->__ckey.unistrlen);
}


std::string	CatalogKey::name()
{
  uint16_t	namelen;
  uint8_t*	key;
  std::string	utf8;
  uint64_t	zero;
  
  key = NULL;
  namelen = this->nameDataLength();
  zero = 0;
  if (((key = this->key()) != NULL) && (this->keyDataLength() >= namelen+CatalogKeyStrOffset))
    {
      utf8 = "";
      UnicodeString us((char*)(key+CatalogKeyStrOffset), namelen, "UTF-16BE");
      //XXX ugly but necessary condition to match HFS Private Data which starts with
      // 4 utf-16 null char...
      // https://developer.apple.com/legacy/library/technotes/tn/tn1150.html#HardLinks
      if (this->parentId() == 2 && namelen > 8 && memcmp(&zero, key+CatalogKeyStrOffset, 8) == 0)
	us.remove(0, 4);
      std::string ret = us.trim().toUTF8String(utf8);
    }
  if (key != NULL)
    free(key);
  return utf8;
}


CatalogKey::Type	CatalogKey::type()
{
  uint8_t*		data;
  uint16_t		_type;
  
  data = NULL;
  _type = CatalogKey::BadRecord;
  if ((data = this->data()) != NULL)
    {
      memcpy(&_type, data, 2);
      _type = bswap16(_type);
    }
  if (data != NULL)
    free(data);
  return (CatalogKey::Type)_type;
}


HfsPermissions::HfsPermissions()
{
}


HfsPermissions::~HfsPermissions()
{
}


void		HfsPermissions::process(Node* origin, uint64_t offset) throw (std::string)
{

}


void		HfsPermissions::process(uint8_t* buffer, uint16_t size) throw (std::string)
{

}


void		HfsPermissions::process(perms permissions) throw (std::string)
{
  memcpy(&this->__permissions, &permissions, sizeof(perms));
}


uint32_t	HfsPermissions::ownerId()
{
  return bswap32(this->__permissions.uid);
}


uint32_t	HfsPermissions::groupId()
{
  return bswap32(this->__permissions.gid);
}


bool		HfsPermissions::isAdminArchived()
{
  return ((this->__permissions.adminFlags & SF_ARCHIVED) == SF_ARCHIVED);
}


bool		HfsPermissions::isAdminImmutable()
{
  return ((this->__permissions.adminFlags & SF_IMMUTABLE) == SF_IMMUTABLE);
}


bool		HfsPermissions::adminAppendOnly()
{
  return ((this->__permissions.adminFlags & SF_APPEND) == SF_APPEND);
}


bool		HfsPermissions::canBeDumped()
{
  return !((this->__permissions.userFlags & UF_NODUMP) == UF_NODUMP);
}


bool		HfsPermissions::isUserImmutable()
{
  return ((this->__permissions.userFlags & UF_IMMUTABLE) == UF_IMMUTABLE);
}

bool		HfsPermissions::userAppendOnly()
{
  return ((this->__permissions.userFlags & UF_APPEND) == UF_APPEND);
}


bool		HfsPermissions::isOpaque()
{
  return ((this->__permissions.userFlags & UF_OPAQUE) == UF_OPAQUE);
}


bool		HfsPermissions::isSuid()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & S_ISUID) == S_ISUID);
}


bool		HfsPermissions::isGid()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & S_ISGID) == S_ISGID);
}


bool		HfsPermissions::stickyBit()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & S_ISTXT) == S_ISTXT);
}


bool		HfsPermissions::isUserReadable()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & S_IRUSR) == S_IRUSR);
}


bool		HfsPermissions::isUserWritable()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & S_IWUSR) == S_IWUSR);
}


bool		HfsPermissions::isUserExecutable()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & S_IXUSR) == S_IXUSR);
}


bool		HfsPermissions::isGroupReadable()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & S_IRGRP) == S_IRGRP);
}

bool		HfsPermissions::isGroupWritable()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & S_IWGRP) == S_IWGRP);
}


bool		HfsPermissions::isGroupExecutable()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & S_IXGRP) == S_IXGRP);
}


bool		HfsPermissions::isOtherReadable()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & S_IROTH) == S_IROTH);
}


bool		HfsPermissions::isOtherWritable()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & S_IWOTH) == S_IWOTH);
}


bool		HfsPermissions::isOtherExecutable()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & S_IXOTH) == S_IXOTH);
}


bool		HfsPermissions::isFifo()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & S_IFIFO) == S_IFIFO);
}


bool		HfsPermissions::isCharacter()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & S_IFCHR) == S_IFCHR);
}


bool		HfsPermissions::isDirectory()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & S_IFDIR) == S_IFDIR);
}


bool		HfsPermissions::isBlock()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & S_IFBLK) == S_IFBLK);
}


bool		HfsPermissions::isRegular()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & S_IFREG) == S_IFREG);
}


bool		HfsPermissions::isSymbolicLink()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & S_IFLNK) == S_IFLNK);
}


bool		HfsPermissions::isSocket()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & S_IFSOCK) == S_IFSOCK);
}


bool		HfsPermissions::isWhiteout()
{
  uint16_t	filemode;

  filemode = bswap16(this->__permissions.fileMode);
  return ((filemode & S_IFWHT) == S_IFWHT);
}


uint32_t	HfsPermissions::linkReferenceNumber()
{
  return bswap32(this->__permissions.special.inodeNum);
}


uint32_t	HfsPermissions::linkCount()
{
  return bswap32(this->__permissions.special.linkCount);
}


uint32_t	HfsPermissions::deviceNumber()
{
  return bswap32(this->__permissions.special.rawDevice);
}


Attributes	HfsPermissions::attributes()
{
  Attributes	attrs;
 
  attrs["uid"] = new Variant(this->ownerId());
  attrs["gid"] = new Variant(this->groupId());
  
  Attributes	aflags;
  aflags["Archived"] = new Variant(this->isAdminArchived());
  aflags["Immutable"] = new Variant(this->isAdminImmutable());
  aflags["Append only"] = new Variant(this->adminAppendOnly());
  attrs["Admin flags"] = new Variant(aflags);

  Attributes	uflags;
  uflags["Dumpable"] = new Variant(this->canBeDumped());
  uflags["Immutable"] = new Variant(this->isUserImmutable());
  uflags["Append only"] = new Variant(this->userAppendOnly());
  attrs["User flags"] = new Variant(uflags);

  Attributes	rights;
  Attributes	umode;
  umode["Read"] = new Variant(this->isUserReadable());
  umode["Write"] = new Variant(this->isUserWritable());
  umode["Execute"] = new Variant(this->isUserExecutable());
  rights["User"] = new Variant(umode);

  Attributes	gmode;
  gmode["Read"] = new Variant(this->isGroupReadable());
  gmode["Write"] = new Variant(this->isGroupWritable());
  gmode["Execute"] = new Variant(this->isGroupExecutable());
  rights["Group"] = new Variant(gmode);

  Attributes	omode;
  omode["Read"] = new Variant(this->isOtherReadable());
  omode["Write"] = new Variant(this->isOtherWritable());
  omode["Execute"] = new Variant(this->isOtherExecutable());
  rights["Other"] = new Variant(gmode);
  attrs["Rights"] = new Variant(rights);

  Attributes	ftype;
  ftype["Named pipe"] = new Variant(this->isFifo());
  ftype["Character"] = new Variant(this->isCharacter());
  ftype["Directory"] = new Variant(this->isDirectory());
  ftype["Block"] = new Variant(this->isBlock());
  ftype["Regular"] = new Variant(this->isRegular());
  ftype["Symbolic link"] = new Variant(this->isSymbolicLink());
  ftype["Socket"] = new Variant(this->isSocket());
  ftype["Whiteout"] = new Variant(this->isWhiteout());
  attrs["File type"] = new Variant(ftype);

  return attrs;
}


CatalogEntry::CatalogEntry()
{
}


CatalogEntry::~CatalogEntry()
{
}


void		CatalogEntry::_readEntry() throw (std::string)
{
  std::string	error;
  VFile*	vfile;
  
  vfile = NULL;
  try
    {
      vfile = this->_origin->open();
      vfile->seek(this->_offset);
      if (vfile->read(&this->_entry, sizeof(catalog_entry)) != sizeof(catalog_entry))
	error = std::string("Cannot read btree node");
    }
  catch (std::string& err)
    {
      error = err;
    }
  catch (vfsError& err)
    {
      error = err.error;
    }
  if (vfile != NULL)
    {
      vfile->close();
      delete vfile;
    }
  if (!error.empty())
    throw error;
}


void		CatalogEntry::process(Node* origin, uint64_t offset) throw (std::string)
{
  this->_origin = origin;
  this->_offset = offset;
  this->_readEntry();
}


void		CatalogEntry::process(uint8_t* buffer, uint16_t size) throw (std::string)
{
  if (size < sizeof(catalog_entry))
    throw std::string("Cannot interpret catalog entry struct because provided buffer is too small");
  memcpy(&this->_entry, buffer, sizeof(catalog_entry));
}


int16_t		CatalogEntry::recordType()
{
  return bswap16(this->_entry.recordType);
}


Attributes	CatalogEntry::commonAttributes()
{
  Attributes		attrs;
  Attributes		aperms;
  HfsPermissions*	perms;

  attrs["created"] = new Variant(this->createDate());
  attrs["content modified"] = new Variant(this->contentModDate());
  attrs["attribute modified"] = new Variant(this->attributeModDate());
  attrs["accessed"] = new Variant(this->accessDate());
  attrs["backup"] = new Variant(this->backupDate());
  perms = new HfsPermissions();
  perms->process(this->_entry.permissions);
  aperms = perms->attributes();  
  attrs["Permissions"] = new Variant(aperms);
  delete perms;
  return attrs;
}


uint32_t	CatalogEntry::id()
{
  return bswap32(this->_entry.id);
}


vtime*	CatalogEntry::createDate()
{
  uint32_t	date;

  date = bswap32(this->_entry.createDate);
  return new HfsVtime(date);
}


vtime*	CatalogEntry::contentModDate()
{
  uint32_t	date;

  date = bswap32(this->_entry.contentModDate);
  return new HfsVtime(date);
}


vtime*	CatalogEntry::attributeModDate()
{
  uint32_t	date;

  date = bswap32(this->_entry.attributeModDate);
  return new HfsVtime(date);
}


vtime*	CatalogEntry::accessDate()
{
  uint32_t	date;

  date = bswap32(this->_entry.accessDate);
  return new HfsVtime(date);
}


vtime*	CatalogEntry::backupDate()
{
  uint32_t	date;

  date = bswap32(this->_entry.backupDate);
  return new HfsVtime(date);
}


HfsNode::HfsNode(HfsNode::Type type, uint32_t parentId, std::string name, fso* fsobj) : Node(name, 0, NULL, fsobj), _parentId(parentId), _type(type)
{
}


bool	HfsNode::_readToBuffer(void* buffer, uint64_t offset, uint16_t size)
{
  bool		success;
  VFile*	vfile;
  
  vfile = NULL;
  success = true;
  try
    {
      vfile = this->_catalog->open();
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


HfsNode::~HfsNode()
{
}

void		HfsNode::process(Node* origin, Node* catalog, uint64_t offset, ExtentsTree* etree)
{
  CatalogEntry*			centry;

  this->_origin = origin;
  this->_catalog = catalog;
  this->_offset = offset;
  this->_etree = etree;
  centry = new CatalogEntry();
  centry->process(catalog, offset);
  this->_cnid = centry->id();
  delete centry;
}


uint32_t	HfsNode::cnid()
{
  return this->_cnid;
}


uint32_t	HfsNode::parentId()
{
  return this->_parentId;
}


uint8_t		HfsNode::hfsType()
{
  return _type;
}


HfsFile::HfsFile(uint32_t parentId, std::string name, fso* fsobj) : HfsNode(HfsNode::File, parentId, name, fsobj)
{
}


HfsFile::~HfsFile()
{
}


void		HfsFile::process(Node* origin, Node* catalog, uint64_t offset, ExtentsTree* etree)
{
  ForkData*	fork;
  
  HfsNode::process(origin, catalog, offset, etree);
  fork = this->dataFork();
  this->setSize(fork->logicalSize());
  delete fork;
}


ForkData*	HfsFile::dataFork()
{
  fork_data	data;
  ForkData*     fork;

  fork = NULL;
  if (this->_readToBuffer(&data, this->_offset+sizeof(catalog_entry), sizeof(fork_data)))
    {
      fork = new ForkData(this->_etree->blockSize());
      //fork = new ForkData(this->_etree->blockSize());
      fork->setExtentsTree(this->_etree);
      fork->setInitialFork(data);
    }
  fork->setFileId(this->cnid());
  return fork;
}



ForkData*	HfsFile::resourceFork()
{
  fork_data	resource;
  ForkData*     fork;

  fork = NULL;
  if (this->_readToBuffer(&resource, this->_offset+sizeof(catalog_entry)+sizeof(fork_data), sizeof(fork_data)))
    {
      fork = new ForkData(this->_etree->blockSize());
      fork->setExtentsTree(this->_etree);
      fork->setInitialFork(resource);
    }
  fork->setFileId(this->cnid());
  return fork;
}


Attributes	HfsFile::_attributes()
{
  CatalogEntry*	centry;
  Attributes	common;
  Attributes	internals;

  centry = new CatalogEntry();
  centry->process(this->_catalog, this->_offset);
  common = centry->commonAttributes();
  internals["offset"] = new Variant(this->_offset);
  internals["id"] = new Variant(this->_cnid);
  internals["parent id"] = new Variant(this->_parentId);
  common["Advanced"] = new Variant(internals);
  delete centry;
  return common;
}


void            HfsFile::fileMapping(FileMapping* fm)
{
  ExtentsList           extents;
  ExtentsList::iterator it;
  uint64_t              coffset;
  ForkData*		fork;

  fork = this->dataFork();
  // if (fork->initialForkSize() < fork->logicalSize())
  //   {
  //     std::cout << this->absolute() << std::endl;
  //     std::cout << "\tid: " << this->cnid() << " -- offset: " << this->_offset << " -- initsize: " << fork->initialForkSize() << " -- logicsize: " << fork->logicalSize() << std::endl;
  //   }
  coffset = 0;
  extents = fork->extents();
  for (it = extents.begin(); it != extents.end(); it++)
    {
      if (coffset + (*it)->size() < fork->logicalSize())
        {
          fm->push(coffset, (*it)->size(), this->_origin, (*it)->startOffset());
          coffset += (*it)->size();
        }
      else
        {
          fm->push(coffset, fork->logicalSize() - coffset, this->_origin, (*it)->startOffset());
          coffset += fork->logicalSize() - coffset;
        }
    }
  delete fork;
}


HfsFolder::HfsFolder(uint32_t parentId, std::string name, fso* fsobj) : HfsNode(HfsNode::Folder, parentId, name, fsobj)
{
}


HfsFolder::~HfsFolder()
{
}


void		HfsFolder::process(Node* origin, Node* catalog, uint64_t offset, ExtentsTree* etree)
{
  HfsNode::process(origin, catalog, offset, etree);
}


Attributes	HfsFolder::_attributes()
{
  CatalogEntry*	centry;
  Attributes	common;
  Attributes	internals;

  centry = new CatalogEntry();
  centry->process(this->_catalog, this->_offset);
  common = centry->commonAttributes();
  internals["offset"] = new Variant(this->_offset);
  internals["id"] = new Variant(this->_cnid);
  internals["parent id"] = new Variant(this->_parentId);
  common["Advanced"] = new Variant(internals);
  delete centry;
  return common;
}
