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
      HFS_ISUID2	= 0x800,     /* set user id on execution */
      HFS_ISGID2	= 0x400,     /* set group id on execution */
      HFS_ISTXT	= 0x200,     /* sticky bit */

      HFS_IRWXU2	= 0x1c0,     /* RWX mask for owner */
      HFS_IRUSR2	= 0x100,     /* R for owner */
      HFS_IWUSR2	= 0x80,     /* W for owner */
      HFS_IXUSR2	= 0x40,     /* X for owner */

      HFS_IRWXG2	= 0x38,     /* RWX mask for group */
      HFS_IRGRP2	= 0x20,     /* R for group */
      HFS_IWGRP2	= 0x10,     /* W for group */
      HFS_IXGRP2	= 0x08,     /* X for group */

      HFS_IRWXO2	= 0x07,     /* RWX mask for other */
      HFS_IROTH2	= 0x04,     /* R for other */
      HFS_IWOTH2	= 0x02,     /* W for other */
      HFS_IXOTH2	= 0x01,     /* X for other */

      HFS_IFMT2	= 0xf000,    /* type of file mask */
      HFS_IFIFO2	= 0x1000,    /* named pipe (fifo) */
      HFS_IFCHR2	= 0x2000,    /* character special */
      HFS_IFDIR2	= 0x4000,    /* directory */
      HFS_IFBLK2	= 0x6000,    /* block special */
      HFS_IFREG2	= 0x8000,   /* regular */
      HFS_IFLNK2	= 0xa000,    /* symbolic link */
      HFS_IFSOCK2	= 0xc000,    /* socket */
      HFS_IFWHT2	= 0xe000    /* whiteout */
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
