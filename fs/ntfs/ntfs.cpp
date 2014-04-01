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
#include <iostream>

#include "ntfs.hpp"
#include "ntfsopt.hpp"
#include "bootsector.hpp"
#include "mftentrynode.hpp"
#include "mftnode.hpp"
#include "mftattributecontent.hpp"
#include "mftattribute.hpp"
#include "mftmanager.hpp"
/*
 *  NTFS 
 */

NTFS::NTFS() : mfso("NTFS"), __opt(NULL), __rootDirectoryNode(new Node("NTFS")), __orphansNode(new Node("orphans")), __bootSectorNode(NULL), __mftManager(NULL)
{
}

NTFS::~NTFS()
{
  if (this->__bootSectorNode)
    delete this->__bootSectorNode;
  if (this->__rootDirectoryNode)
    delete this->__rootDirectoryNode;
  if (this->__mftManager)
    delete this->__mftManager;
}

void    NTFS::start(Attributes args)
{
  this->__opt = new NTFSOpt(args);
  this->__bootSectorNode = new BootSectorNode(this);
  if (this->__opt->validateBootSector())
    this->__bootSectorNode->validate();

  /* 
   * GET MFT NODE 
   */ 
  this->setStateInfo("Reading main MFT");
  MFTNode* mftNode = new MFTNode(this, this->fsNode(), this->rootDirectoryNode(),  this->__bootSectorNode->MFTLogicalClusterNumber() * this->__bootSectorNode->clusterSize());

  this->__mftManager = new MFTEntryManager(this, mftNode);
  this->__mftManager->linkEntries(); 
  this->__mftManager->linkOrphanEntries();

  this->registerTree(this->opt()->fsNode(), this->rootDirectoryNode());

  this->setStateInfo("finished successfully");
  this->res["Result"] = Variant_p(new Variant(std::string("NTFS parsed successfully.")));
}

NTFSOpt*	NTFS::opt(void) const
{
  return (this->__opt);
}

Node*		NTFS::fsNode(void) const
{
  return (this->__opt->fsNode());
}

Node*           NTFS::orphansNode(void) const
{
  return (this->__orphansNode);
}

void 		NTFS::setStateInfo(const std::string& info)
{
  this->stateinfo = std::string(info);
}

Node*		NTFS::rootDirectoryNode(void) const
{
  return (this->__rootDirectoryNode);
}

BootSectorNode*	NTFS::bootSectorNode(void) const
{
  return (this->__bootSectorNode);
}

int32_t  NTFS::vread(int fd, void *buff, unsigned int size)
{
  return (mfso::vread(fd, buff, size));
  fdinfo* fi = NULL;
  try
  {
    fi = this->__fdmanager->get(fd);
  }
  catch (vfsError& e)
  {
    return (0); 
  }
  catch (std::string const& e)
  {
    return (0);
  }
 
  MFTNode* mftNode = dynamic_cast<MFTNode* >(fi->node);
  if (mftNode == NULL)
    return (mfso::vread(fd, buff, size));

  if (fi->offset > mftNode->size())
    return (0);

  //std::vector<MFTAttributeContent*> datas = mftNode->data(); //too slow
  //std::vector<MFTAttributeContent*>::iterator data = datas.begin();
  //if (!datas.size())
    //return (mfso::vread(fd, buff, size)); //can have a mapped attribute !
    ////return (0); 
  //if (!datas[0]->mftAttribute()->isCompressed())
  //{
    //for (;data != datas.end(); ++data)
      //delete (*data);
    //return (mfso::vread(fd, buff, size));
  //}

  uint32_t readed = 0;
  //uint32_t compressionBlockSize = 0;
  //try
  //{
    //int32_t attributecount = 0;
    //for (; (readed < size) && (data != datas.end()); ++data)
    //{
      //if (!compressionBlockSize)
        //compressionBlockSize = (*data)->mftAttribute()->compressionBlockSize();
      //uint64_t start = (*data)->mftAttribute()->VNCStart() * this->bootSectorNode()->clusterSize();
      //uint64_t end = (*data)->mftAttribute()->VNCEnd() * this->bootSectorNode()->clusterSize();
      //if ((start <= fi->offset) && (fi->offset < end))
      //{
        //int32_t read = (*data)->uncompress(fi->offset, (uint8_t*)buff + readed, size - readed, compressionBlockSize);
        //if (read  <= 0)
          //break; //can return  
        //if (fi->offset + read > mftNode->size())
        //{
          //readed += mftNode->size() - fi->offset;
          //fi->offset = mftNode->size();
          //break; //cant return
        //}
        //fi->offset += read;
        //readed += read;
      //}
      //attributecount++;
      //delete (*data);
    //}
    //for (;data != datas.end(); ++data)
      //delete (*data);
  //}
  //catch (std::string const & error)
  //{
    //std::cout << "Error in data attribute : " << error << std::endl;
    ////for datas.end() delete
  //}
  return (readed);
}
