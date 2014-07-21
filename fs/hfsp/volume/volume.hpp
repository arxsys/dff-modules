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


#ifndef __HFSP_VOLUME_HPP__
#define __HFSP_VOLUME_HPP__

#include <stdint.h>

#include "export.hpp"
#include "node.hpp"
#include "vtime.hpp"

#include "endian.hpp"

#include "extents/fork.hpp"

// Following defines are used in volume_header.signature
#define HfspVolume	0x482b // H+
#define HfsxVolume	0x4858 // HX

// Following defines are used in volume_header.version
#define Journaled	0x4846534a // HFSJ
#define MacOs		0x382e3130 // 8.10
#define MacOsX		0x31302e30 // 10.0
#define Fsck		0x6673636b // fsck

// Following defines are used in volume_header.attributes
#define VolumeUmounted		(1<<8)
#define VolumeSparedBlocks	(1<<9)
#define VolumeNoCacheRequired	(1<<10)
#define	BootVolumeInconsistent	(1<<11)
#define	CatalogNodeIDsReused	(1<<12)
#define	VolumeJournaled		(1<<13)
#define VolumeSoftwareLock	(1<<14)


PACK_START
typedef struct s_volumeheader
{
  uint16_t	signature; // H+ or HX
  uint16_t	version;
  uint32_t	attributes;
  uint32_t	lastMountedVersion;
  uint32_t	journalInfoBlock;
 
  uint32_t	createDate;
  uint32_t	modifyDate;
  uint32_t	backupDate;
  uint32_t	checkedDate;
 
  uint32_t	fileCount;
  uint32_t	folderCount;
 
  uint32_t	blockSize;
  uint32_t	totalBlocks;
  uint32_t	freeBlocks;
 
  uint32_t	nextAllocation;
  uint32_t	rsrcClumpSize;
  uint32_t	dataClumpSize;
  uint32_t	nextCatalogID;

  uint32_t	writeCount;
  uint64_t	encodingsBitmap;

  uint32_t	finderInfo[8];
  
  fork_data	allocationFile;
  fork_data	extentsFile;
  fork_data	catalogFile;
  fork_data	attributesFile;
  fork_data	startupFile;
}		volumeheader;
PACK_END


class VolumeHeader
{
private:
  volumeheader	__vheader;

public:
  VolumeHeader();
  ~VolumeHeader();
  void		process(Node* origin, fso* fsobj) throw (std::string);
  Attributes	_attributes();

  uint16_t	signature();
  uint16_t	version();
  uint32_t	attributes();
  uint32_t	lastMountedVersion();
  uint32_t	journalInfoBlock();

  vtime*	createDate();
  vtime*	modifyDate();
  vtime*	backupDate();
  vtime*	checkedDate();
 
  uint32_t	fileCount();
  uint32_t	folderCount();
 
  uint32_t	blockSize();
  uint32_t	totalBlocks();
  uint32_t	freeBlocks();
 
  uint32_t	nextAllocation();
  uint32_t	rsrcClumpSize();
  uint32_t	dataClumpSize();
  uint32_t	nextCatalogID();

  uint32_t	writeCount();
  uint64_t	encodingsBitmap();

  fork_data	allocationFile();
  fork_data	extentsFile();
  fork_data	catalogFile();
  fork_data	attributesFile();
  fork_data	startupFile();
  
  bool		isHfspVolume();
  bool		isHfsxVolume();
  bool		createdByFsck();
  bool		isJournaled();
  bool		isMacOsX();
  bool		isMacOs();
  bool		correctlyUmount();
  bool		hasBadBlocksExtents();
  bool		isRamDisk();
  bool		isCatalogIdReused();
  bool		isWriteProtected();
};


#endif
