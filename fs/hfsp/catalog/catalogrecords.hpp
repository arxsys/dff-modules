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

#ifndef __CATALOG_RECORDS_HPP__
#define __CATALOG_RECORDS_HPP__

#include <stdint.h>

#include "export.hpp"
#include "node.hpp"
#include "vfile.hpp"

#include "endian.hpp"
#include "finder.hpp"
#include "extents/fork.hpp"

#define CatalogKeyStrOffset	8

PACK_START
typedef struct s_catalog_key
{
  uint16_t	keyLength;
  uint32_t	parentId;
  uint16_t	unistrlen;  
}		catalog_key;
PACK_END

//XXX what's the best ? Letting tree create catalog entry or catalog key
// provides a create() method returning object based on type (factory) ?
class CatalogKey : public KeyedRecord
{
private:
  catalog_key	__ckey;
public:
  typedef enum
    {
      BadRecord		= 0x0000,
      FolderRecord	= 0x0001,
      FileRecord	= 0x0002,
      FolderThread	= 0x0003,
      FileThread	= 0x0004
    } Type;
  CatalogKey();
  ~CatalogKey();
  void			process(Node* origin, uint64_t offset, uint16_t size) throw (std::string);
  uint32_t		parentId();
  uint16_t		nameDataLength();
  uint16_t		nameLength();
  std::string		name();
  CatalogKey::Type	type();
};


PACK_START
typedef struct s_perms_info
{
  uint32_t	uid;
  uint32_t	gid;
  uint8_t	adminFlags;
  uint8_t	userFlags;
  uint16_t	fileMode;
  union
  {
    uint32_t	inodeNum;
    uint32_t	linkCount;
    uint32_t	rawDevice;
  }		special;
}		perms;
PACK_END


class HfsPermissions
{
private:
  perms		__permissions;
  typedef enum
    {
      SF_ARCHIVED	= 0x01,
      SF_IMMUTABLE	= 0x02,
      SF_APPEND		= 0x04
    } AdminFlags;
  typedef enum
    {
      UF_NODUMP		= 0x01,
      UF_IMMUTABLE	= 0x02,
      UF_APPEND		= 0x04,
      UF_OPAQUE		= 0x08
    } UserFlags;
  typedef enum
    {
      S_ISUID	= 0x800,     /* set user id on execution */
      S_ISGID	= 0x400,     /* set group id on execution */
      S_ISTXT	= 0x200,     /* sticky bit */

      S_IRWXU	= 0x1c0,     /* RWX mask for owner */
      S_IRUSR	= 0x100,     /* R for owner */
      S_IWUSR	= 0x80,     /* W for owner */
      S_IXUSR	= 0x40,     /* X for owner */

      S_IRWXG	= 0x38,     /* RWX mask for group */
      S_IRGRP	= 0x20,     /* R for group */
      S_IWGRP	= 0x10,     /* W for group */
      S_IXGRP	= 0x08,     /* X for group */

      S_IRWXO	= 0x07,     /* RWX mask for other */
      S_IROTH	= 0x04,     /* R for other */
      S_IWOTH	= 0x02,     /* W for other */
      S_IXOTH	= 0x01,     /* X for other */

      S_IFMT	= 0xf000,    /* type of file mask */
      S_IFIFO	= 0x1000,    /* named pipe (fifo) */
      S_IFCHR	= 0x2000,    /* character special */
      S_IFDIR	= 0x4000,    /* directory */
      S_IFBLK	= 0x6000,    /* block special */
      S_IFREG	= 0x8000,   /* regular */
      S_IFLNK	= 0xa000,    /* symbolic link */
      S_IFSOCK	= 0xc000,    /* socket */
      S_IFWHT	= 0xe000    /* whiteout */
    } FileMode;

public:
  HfsPermissions();
  ~HfsPermissions();
  void		process(Node* origin, uint64_t offset) throw (std::string);
  void		process(uint8_t* buffer, uint16_t size) throw (std::string);
  void		process(perms permissions) throw (std::string);
  uint32_t	ownerId();
  uint32_t	groupId();
  bool		isAdminArchived();
  bool		isAdminImmutable();
  bool		adminAppendOnly();
  bool		canBeDumped();
  bool		isUserImmutable();
  bool		userAppendOnly();
  bool		isOpaque();
  bool		isSuid();
  bool		isGid();
  bool		stickyBit();
  bool		isUserReadable();
  bool		isUserWritable();
  bool		isUserExecutable();
  bool		isGroupReadable();
  bool		isGroupWritable();
  bool		isGroupExecutable();
  bool		isOtherReadable();
  bool		isOtherWritable();
  bool		isOtherExecutable();
  bool		isFifo();
  bool		isCharacter();
  bool		isDirectory();
  bool		isBlock();
  bool		isRegular();
  bool		isSymbolicLink();
  bool		isSocket();
  bool		isWhiteout();
  uint32_t	linkReferenceNumber();
  uint32_t	linkCount();
  uint32_t	deviceNumber();
  Attributes	attributes();
};


PACK_START
typedef struct s_catalog_entry
{
  int16_t	recordType;
  uint16_t	flags;
  uint32_t	valence; // not used by file
  uint32_t	id;
  uint32_t	createDate;
  uint32_t	contentModDate;
  uint32_t	attributeModDate;
  uint32_t	accessDate;
  uint32_t	backupDate;
  perms		permissions;
  uint8_t	userInfo[16];
  uint8_t	finderInfo[16];
  uint32_t	textEncoding;
  uint32_t	reserved;
}		catalog_entry;
PACK_END


class CatalogEntry 
{
protected:
  Node*			_origin;
  uint64_t		_offset;
  catalog_entry		_entry;
  HfsPermissions*	_permissions;
  void			_readEntry() throw (std::string);
  vtime*		createDate();
  vtime*		contentModDate();
  vtime*		attributeModDate();
  vtime*		accessDate();
  vtime*		backupDate();
public:
  CatalogEntry();
  virtual ~CatalogEntry();
  void		process(Node* origin, uint64_t offset) throw (std::string);
  void		process(uint8_t* buffer, uint16_t size) throw (std::string);
  int16_t	recordType();
  Attributes	commonAttributes();
  uint32_t	id();
};


class HfsNode : public Node
{
public:
  typedef enum
    {
      File	= 0x0001,
      Folder	= 0x0002
    } Type;
protected:
  //CatalogEntry*	_centry;
  uint32_t	_cnid;
  uint32_t	_parentId;
  HfsNode::Type	_type;
  Node*		_origin;
  Node*		_catalog;
  uint64_t	_offset;
  ExtentsTree*	_etree;
  bool		_readToBuffer(void* buffer, uint64_t offset, uint16_t size);
public:
  HfsNode(HfsNode::Type type, uint32_t parentId, std::string name, fso* fosbj);
  virtual ~HfsNode();
  virtual void	process(Node* origin, Node* catalog, uint64_t offset, ExtentsTree* etree);
  uint32_t	cnid();
  uint32_t	parentId();
  uint8_t	hfsType();
};


class HfsFile : public HfsNode
{
public:
  HfsFile(uint32_t parentId, std::string name, fso* fsobj);
  ~HfsFile();
  void		process(Node* origin, Node* catalog, uint64_t offset, ExtentsTree* etree);
  uint32_t	fileId();
  void		fileMapping(FileMapping* fm);
  ForkData*	dataFork();
  ForkData*	resourceFork();
  Attributes	_attributes();
};


class HfsFolder : public HfsNode
{
public:
  HfsFolder(uint32_t parentId, std::string name, fso* fsobj);
  ~HfsFolder();
  void	process(Node* origin, Node* catalog, uint64_t offset, ExtentsTree* etree);
  Attributes	_attributes();
};


#endif
