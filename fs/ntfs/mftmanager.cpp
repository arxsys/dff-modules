/* DFF -- An Open Source Digital Forensics Framework
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

#include "mftmanager.hpp"
#include "ntfs.hpp"
#include "mftnode.hpp"
#include "bootsector.hpp"
#include "mftattributecontenttype.hpp"

MFTEntryManager::MFTEntryManager(NTFS* ntfs, MFTNode* mftNode) : __ntfs(ntfs), __masterMFTNode(mftNode)
{
  this->__numberOfEntry = this->__masterMFTNode->size() / this->__ntfs->bootSectorNode()->MFTRecordSize();
  this->initEntries();
}

uint64_t MFTEntryManager::entryCount(void) const
{
  return (this->__numberOfEntry);
}

bool    MFTEntryManager::exist(uint64_t id) const
{
  std::map<uint64_t, MFTEntryInfo>::const_iterator entry = this->__entries.find(id);
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
  if (this->__entries[id].node == NULL)
    std::cout << "Adding to a non-existent entry " << id << " child " << childId << std::endl;
  this->__entries[id].childrenId.push_back(childId);
  this->__entries[id].childrenId.sort(); //do it every time ?
  this->__entries[id].childrenId.unique();

  return (true);
}

MFTNode*  MFTEntryManager::node(uint64_t id) const
{
  std::map<uint64_t, MFTEntryInfo>::const_iterator entry = this->__entries.find(id);
  if (entry != this->__entries.end()) //if node exist
    return ((*entry).second.node);
  return (NULL);
}

bool MFTEntryManager::addChildId(uint64_t nodeId, MFTNode* node)
{
  std::vector<IndexEntry> indexes = node->indexes();
  std::vector<IndexEntry>::iterator index = indexes.begin();
  if (indexes.size() == 0)
    return (true);
  for (; index != indexes.end(); ++index)
  {
    uint64_t entryId = (*index).mftEntryId();

    if (entryId == 0) //end of list
      continue;
    this->add(nodeId, entryId);
  }
  return (true);
}

bool MFTEntryManager::addChild(uint64_t nodeId)
{
  Node* node = this->node(nodeId);
  
  if (node == NULL) 
  {
    std::cout << "parent " << nodeId << " not found !" << std::endl;
    return (false);
  }
  std::list<uint64_t> childrenId = this->__entries[nodeId].childrenId;
  std::list<uint64_t>::iterator childId = childrenId.begin();

  if (childrenId.size() == 0)
    return (false);
  for (; childId != childrenId.end(); ++childId)
  {
    if (*childId == 0) //end of list
      continue;
    Node* child = this->node(*childId);
    if (child)
      node->addChild(child);
    else
      std::cout << "Child not ofund !" << std::endl;
    //this->add(nodeId, entryId);
  }
  return (true);
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
      std::cout << "id " << id << " child id " << childId << " subchild " <<  *subchild << std::endl;
      this->__entries[childId].childrenId.remove(*subchild);
      //this->inChildren(id, childId); 
     //break; // remove from iterator ? 
    }
    this->inChildren(id, *subchild);
  }
}

void MFTEntryManager::childrenSanitaze(void)
{
  //avoid infinit loop in nested directory
  std::map<uint64_t, MFTEntryInfo >::iterator  entry = this->__entries.begin();
  for (; entry != this->__entries.end(); entry++)
     this->inChildren(entry->first, entry->first);
}

/*
 *  Create all MFT Entry 
 */
void MFTEntryManager::initEntries(void)
{
  std::ostringstream nMFTStream;
  nMFTStream  << std::string("Found ") << this->__numberOfEntry <<  std::string(" MFT entry") << endl;
  this->__ntfs->setStateInfo(nMFTStream.str());

  uint32_t mftRecordSize = this->__ntfs->bootSectorNode()->MFTRecordSize();
  for(uint64_t id = 0; id < this->__numberOfEntry; ++id)
  {
    if (id % 1000 == 0)
    {
      std::ostringstream cMFTStream;
      cMFTStream << "Parsing " << id << "/" << this->__numberOfEntry;
      std::cout << cMFTStream.str() << std::endl;
      this->__ntfs->setStateInfo(cMFTStream.str());
    }
    try 
    {
      MFTNode* currentMFTNode = new MFTNode(this->__ntfs, this->__masterMFTNode, NULL, id * mftRecordSize); 
      this->add(id, currentMFTNode);
    }
    catch (std::string& error)
    {
      std::cout << "Can't create MFTNode" << id << " error: " << error << std::endl;
    }
  }
}

/*
 *  Link node to parent
 */  
void MFTEntryManager::linkEntries(void)
{
  this->childrenSanitaze();
  for(uint64_t id = 0; id < this->__numberOfEntry; ++id)
  {
    if (id % 1000 == 0)
      std::cout << "linking node " << id << std::endl;
    this->addChild(id); 
  }

  /* mount root '.' as 'ntfs/root/' */
  MFTNode* rootMFT = this->node(5);
  if (rootMFT)
  {
    rootMFT->setName("root"); //replace '.'
    this->__ntfs->rootDirectoryNode()->addChild(rootMFT);
  }
  else
    std::cout << "No root found" << std::endl;
}

void MFTEntryManager::linkOrphanEntries(void)
{
  ///* search for orphan node */
  for(uint64_t id = 0; id < this->__numberOfEntry; ++id)
  {
    MFTNode* mftNode = this->node(id); 
    if (mftNode && (mftNode->parent() == NULL))
    {
      std::vector<MFTAttribute* > attributes = mftNode->mftEntryNode()->MFTAttributesType($FILE_NAME);  //XXX use filename relocation 
      std::vector<MFTAttribute* >::iterator attribute = attributes.begin();//XXX use filename relocation 
      if (attributes.size())
      {
        FileName* fileName = dynamic_cast<FileName*>((*attribute)->content());
        uint64_t parentId = fileName->parentMFTEntryId();
        
        MFTNode* parent = this->node(parentId);
        if (parent)
        {
          if (fileName->parentSequence() != parent->mftEntryNode()->sequence())
          {
             std::cout << "PARENT " << mftNode->name() << " and parent  " << parent->name() << " Have != seq  " << std::endl;
             ///XXX also can if check is mftNode.isDirectory() // car si non c bien reecrit c chelou         
             //par ex les images de meg0 rien a voir     
             this->__ntfs->orphansNode()->addChild(mftNode);
          }
          //else
          //std::cout << "aprent and son sequence ok " << std::endl;
          else 
            parent->addChild(mftNode);
                //delete fileName /dellte for in *attribute .. continue 
                //std::cout << "oprhan " << mftNode->name() << " found in existing parent " << parent->name() << std::endl;
          continue;
        }
        else 
          std::cout << "orphan with parent found but parent not found ! " << parentId << std::endl;
       
        //XXX XX check sequence en + (peut etre lie au meme rep avant avec sequence differente)
        // XXX checkfilename en + peut etre lie a une mftID mais la mftID est detruit et new rep cree
        // donc linke a un movais rep !
 
        delete fileName;
      }
      else
        this->__ntfs->orphansNode()->addChild(mftNode);
      for (; attribute != attributes.end(); ++attribute)
        delete (*attribute);
    }
  }
  //ddif orphans->childCount();
  this->__ntfs->rootDirectoryNode()->addChild(this->__ntfs->orphansNode());
}

