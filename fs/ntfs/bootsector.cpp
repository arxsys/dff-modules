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

#include "bootsector.hpp"
#include "ntfs.hpp"
#include "ntfsopt.hpp"

BootSectorNode::BootSectorNode(NTFS* ntfs) : Node(std::string("$Boot"), 512, ntfs->rootDirectoryNode(), ntfs)
{
//  this->__ntfs->setStateInfo(std::string("Parsing NTFS boot sector"));
  this->__ntfs = ntfs;
  this->__bootSector = new BootSector; //XNEW 

//1) This trigger MFSO CACHE !!! and set the size to 512 ! 
  VFile* vfile = this->open();
  uint64_t readed = vfile->read((void*) (this->__bootSector), sizeof(BootSector));
  vfile->close();

  if (readed != sizeof(BootSector))
    throw vfsError(std::string("Can't read start of boot sector"));

//2) MFSO CACHE ALREADY TRIGER SO FUCKED !!! MUST PATCH MFSO PATCH -> to check size or reput in cache
  if (ntfs->fsNode()->size() > this->bytesPerSector() * 16)
    this->setSize(this->bytesPerSector() * 16);
  else 
    throw vfsError(std::string("Can't read full boot sector"));
} 

void	BootSectorNode::validate()
{
  this->__ntfs->setStateInfo("Validating NTFS boot sector");
  if (this->endOfSector() != 0xAA55)
    throw vfsError(std::string("Boot sector as an invalid end of sector value")); 
  if (this->bytesPerSector() == 0 || this->bytesPerSector() % 512)
    throw vfsError(std::string("Boot sector as an invalid bytes per sector value"));
  if (this->sectorsPerCluster() == 0)
    throw vfsError(std::string("Boot sector as an invalid sector per cluster value"));
  if (this->totalSectors() == 0) 
    throw vfsError(std::string("Boot sector as an invalid total sectors value"));
  if ((this->MFTLogicalClusterNumber() > this->totalSectors()) && (this->MFTMirrorLogicalClusterNumber() > this->totalSectors()))
    throw vfsError(std::string("Boot sector can't resolve a valid MTF cluster"));
  if (this->clustersPerMFTRecord() == 0)
    throw vfsError(std::string("Boot sector as an invalid cluster per MFT record value"));
  if (this->clustersPerIndexBuffer() == 0)
    throw vfsError(std::string("Boot sector as an invalid cluster per index buffer value"));
}

BootSectorNode::~BootSectorNode()
{
  delete this->__bootSector;
  this->__bootSector = NULL;
}

void 		BootSectorNode::fileMapping(FileMapping *fm)
{
  fm->push(0, this->size(), this->__ntfs->fsNode(), 0);
}

Attributes      BootSectorNode::_attributes(void)
{
  Attributes    attrs;

  attrs["OEM ID"] = Variant_p(new Variant(this->OEMDID()));
  attrs["Bytes per sector"] = Variant_p(new Variant(this->bytesPerSector()));
  attrs["Sectors per cluster"] = Variant_p(new Variant(this->sectorsPerCluster()));
  attrs["Cluster size"] = Variant_p(new Variant(this->clusterSize()));
//XXX if string ..
  attrs["Media descriptor"] = Variant_p(new Variant(this->mediaDescriptor()));

  attrs["Total sectors"] = Variant_p(new Variant(this->totalSectors()));
  attrs["MFT logical cluster number"] = Variant_p(new Variant(this->MFTLogicalClusterNumber()));
  attrs["MFT mirror logical cluster number"] = Variant_p(new Variant(this->MFTMirrorLogicalClusterNumber()));
  attrs["Clusters per MFT record"] = Variant_p(new Variant(this->clustersPerMFTRecord()));
  attrs["MFT entry size"] = Variant_p(new Variant(this->MFTRecordSize())); //MFT Record Size ? 
  attrs["Clusters per index buffer"] = Variant_p(new Variant(this->clustersPerIndexBuffer()));
  attrs["Volume serial number"] = Variant_p(new Variant(this->volumeSerialNumber()));
  attrs["End of sector"] = Variant_p(new Variant(this->endOfSector()));
 
  return attrs;
}

Attributes	BootSectorNode::dataType(void)
{
  Attributes    attrs;

  attrs["ntfs"] = Variant_p(new Variant(std::string("ntfs bootsector")));

  return attrs;
}

uint64_t 	BootSectorNode::OEMDID(void)
{
  return (this->__bootSector->OEMID);
};

uint16_t 	BootSectorNode::bytesPerSector(void) //sectorSize ...
{
  return (this->__bootSector->bpb.bytesPerSector);
};

uint8_t		BootSectorNode::sectorsPerCluster(void)
{
  return (this->__bootSector->bpb.sectorsPerCluster);
};

uint32_t	BootSectorNode::clusterSize(void)
{
 return (this->__bootSector->bpb.sectorsPerCluster * this->__bootSector->bpb.bytesPerSector);
}

uint8_t		BootSectorNode::mediaDescriptor(void)
{
  return (this->__bootSector->bpb.mediaDescriptor);
};
uint64_t	BootSectorNode::totalSectors(void)
{
  return (this->__bootSector->bpb.totalSectors);
};

uint64_t BootSectorNode::MFTLogicalClusterNumber(void)
{
  return (this->__bootSector->bpb.MFTLogicalClusterNumber);
};

uint64_t	BootSectorNode::MFTMirrorLogicalClusterNumber(void)
{
  return (this->__bootSector->bpb.MFTMirrorLogicalClusterNumber);
};

int8_t		BootSectorNode::clustersPerMFTRecord(void)
{
  return (this->__bootSector->bpb.clustersPerMFTRecord);
};

uint32_t	BootSectorNode::MFTRecordSize(void)
{
  return (this->__bootSector->bpb.clustersPerMFTRecord * this->__bootSector->bpb.sectorsPerCluster * this->__bootSector->bpb.bytesPerSector);
};

int8_t		BootSectorNode::clustersPerIndexBuffer(void)
{
  return (this->__bootSector->bpb.clustersPerIndexBuffer);
};

uint64_t	BootSectorNode::volumeSerialNumber(void)
{
  return (this->__bootSector->bpb.volumeSerialNumber);
};

uint16_t	BootSectorNode::endOfSector(void)
{
  return (this->__bootSector->endOfSector);
};
