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


#include "permissions.hpp"


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