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

MFTEntryManager::MFTEntryManager(void)
{
}

bool    MFTEntryManager::exist(uint64_t id)
{
  std::map<uint64_t, MFTEntryInfo>::iterator entry = this->__entries.find(id);
  if (entry != this->__entries.end()) //if node exist
  {
    if ((*entry).second.node == NULL)
       return (false);
    return (true);
  }
  return (false);
}


bool    MFTEntryManager::add(uint64_t id, MFTNode* node)
{
  if (this->exist(id) == false)
  {
    this->__entries[id].node = node;
    this->addChildId(id, node);
  }
  return (true);
}

bool MFTEntryManager::add(uint64_t id, uint64_t childId)
{
//sanitaze !
  this->__entries[id].childrenId.push_back(childId);
  this->__entries[id].childrenId.sort(); //do it every time ?
  this->__entries[id].childrenId.unique();
  return (true);
}


MFTNode*  MFTEntryManager::node(uint64_t id)
{
  if (this->exist(id)) 
    return (this->__entries[id].node);
  return (NULL);
}


NTFS::NTFS() : mfso("NTFS"), __opt(NULL), __rootDirectoryNode(new Node("NTFS")), __orphansNode(new Node("orphans")), __bootSectorNode(NULL)
{
}

NTFS::~NTFS()
{
  if (this->__bootSectorNode)
    delete this->__bootSectorNode;
  if (this->__rootDirectoryNode)
    delete this->__rootDirectoryNode;
}

void MFTEntryManager::inChildren(uint64_t id, uint64_t childId)
{
  std::list<uint64_t> subchildrenId = this->__entries[childId].childrenId;
  std::list<uint64_t>::iterator subchild = subchildrenId.begin();
  for (; subchild != subchildrenId.end(); ++subchild)
  {
    if (id == *subchild)
    {
      std::cout << "found a loop (remove it) " << std::endl;
      this->__entries[childId].childrenId.remove(*subchild);
      inChildren(id, childId); 
     //break; // remove from iterator ? 
    }
    inChildren(id, *subchild);
  }
}

void MFTEntryManager::childrenSanitaze(void)
{
  //avoid infinit loop in nested directory
  std::map<uint64_t, MFTEntryInfo >::iterator  entry = this->__entries.begin();
  for (; entry != this->__entries.end(); entry++)
     this->inChildren(entry->first, entry->first);
}

bool MFTEntryManager::addChildId(uint64_t nodeId, MFTNode* node)
{
  std::vector<IndexEntry> indexes = node->indexes();
  std::vector<IndexEntry>::iterator index = indexes.begin();
  if (indexes.size() == 0)
    return true;
  for (; index != indexes.end(); ++index)
  {
    uint64_t entryId = (*index).mftEntryId();

    if (entryId == 0) //end of list
      continue;
    this->add(nodeId, entryId);
  }
  return true;
}

bool MFTEntryManager::addChild(uint64_t nodeId)
{
  Node* node = this->node(nodeId);
  if (node == NULL) 
    return (false);
  std::list<uint64_t> childrenId = this->__entries[nodeId].childrenId;
  std::list<uint64_t>::iterator childId = childrenId.begin();

  if (childrenId.size() == 0)
    return false;
  for (; childId != childrenId.end(); ++childId)
  {
    if (*childId == 0) //end of list
      continue;
    Node* child = this->node(*childId);
    if (child)
      node->addChild(child);
    //this->add(nodeId, entryId);
  }
  return true;
}

void 		NTFS::start(Attributes args)
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
//  this->__mftManager->add(mftNode, 0);
//  this->__mftManager->add(mftNode, 1); get mirror et compare ? MFTManager(mirror) 

  /*
   *  Create all MFT Entry 
   */
  uint64_t id = 0;
  uint64_t nMFT = mftNode->size() / this->bootSectorNode()->MFTRecordSize();
  std::ostringstream nMFTStream;
  nMFTStream  << std::string("Found ") << nMFT <<  std::string(" MFT entry") << endl;
  this->setStateInfo(nMFTStream.str());

  /* create node for each mftenty */
  while (id * this->bootSectorNode()->MFTRecordSize() < mftNode->size())
  {
   if (id % 1000 == 0)
   {
     std::ostringstream cMFTStream;
     cMFTStream << "Parsing " << id << "/" << nMFT;
     std::cout << cMFTStream.str() << std::endl;
     this->setStateInfo(cMFTStream.str());
   }
   try 
   {
     MFTNode* currentMFTNode = new MFTNode(this, mftNode, NULL, id * this->bootSectorNode()->MFTRecordSize());
     this->__mftManager.add(id, currentMFTNode);
   }
   catch (std::string& error)
   {
     std::cout << "Can't create MFTNode" << id << " error: " << error << std::endl;
   }
   id++;
  }

  /* link node to parent */
  this->__mftManager.childrenSanitaze();
  for(id = 0; id < nMFT; ++id)
  {
    if (id % 1000 == 0)
      std::cout << "linking node " << id << std::endl;
    this->__mftManager.addChild(id); 
  }

  /* mount root '.' mft5 */
  MFTNode* rootMFT = this->__mftManager.node(5);
  if (rootMFT)
  {
    rootMFT->setName("root"); //replace '.'
    this->rootDirectoryNode()->addChild(rootMFT);
  }
  else
    std::cout << "no root" << std::endl;

  /* search for orphan node */
  for(id = 0; id < nMFT; ++id)
  {
    MFTNode* mftNode = this->__mftManager.node(id); 
    if (mftNode && (mftNode->parent() == NULL))
      this->__orphansNode->addChild(mftNode);
  }
  this->rootDirectoryNode()->addChild(this->__orphansNode);
  //if orphans->childCount();

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

  std::vector<MFTAttributeContent*> datas = mftNode->data(); //too slow
  std::vector<MFTAttributeContent*>::iterator data = datas.begin();
  if (!datas.size())
    return (mfso::vread(fd, buff, size)); //can have a mapped attribute !
    //return (0); 
  if (!datas[0]->mftAttribute()->isCompressed())
  {
    for (;data != datas.end(); ++data)
      delete (*data);
    return (mfso::vread(fd, buff, size));
  }

  uint32_t readed = 0;
  uint32_t compressionBlockSize = 0;
  try
  {
    int32_t attributecount = 0;
    for (; (readed < size) && (data != datas.end()); ++data)
    {
      if (!compressionBlockSize)
        compressionBlockSize = (*data)->mftAttribute()->compressionBlockSize();
      uint64_t start = (*data)->mftAttribute()->VNCStart() * this->bootSectorNode()->clusterSize();
      uint64_t end = (*data)->mftAttribute()->VNCEnd() * this->bootSectorNode()->clusterSize();
      if ((start <= fi->offset) && (fi->offset < end))
      {
        int32_t read = (*data)->uncompress(fi->offset, (uint8_t*)buff + readed, size - readed, compressionBlockSize);
        if (read  <= 0)
          break; //can return  
        if (fi->offset + read > mftNode->size())
        {
          readed += mftNode->size() - fi->offset;
          fi->offset = mftNode->size();
          break; //cant return
        }
        fi->offset += read;
        readed += read;
      }
      attributecount++;
      delete (*data);
    }
    for (;data != datas.end(); ++data)
      delete (*data);
  }
  catch (std::string const & error)
  {
    std::cout << "Error in data attribute : " << error << std::endl;
    //for datas.end() delete
  }
  return (readed);
}
