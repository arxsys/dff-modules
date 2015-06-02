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

#ifndef __PERMISSIONS_HPP__
#define __PERMISSIONS_HPP__

#include <stdint.h>

#include "export.hpp"
#include "node.hpp"
#include "vfile.hpp"

#include "endian.hpp"
#include "finder.hpp"
#include "extents/fork.hpp"


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


class HfspPermissions
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
  HfspPermissions();
  ~HfspPermissions();
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


#endif
