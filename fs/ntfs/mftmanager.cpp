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

/**
 *  MFTEntryInfo
 */
MFTEntryInfo::MFTEntryInfo(MFTNode* _node) : id(0), linked(false), node(_node)
{
}

MFTEntryInfo::~MFTEntryInfo()
{
//delete node & unlink
}

/**
 *  MFTEntryManager
 */
MFTEntryManager::MFTEntryManager(NTFS* ntfs, MFTNode* mftNode) : __ntfs(ntfs), __masterMFTNode(mftNode)
{
  this->__numberOfEntry = this->__masterMFTNode->size() / this->__ntfs->bootSectorNode()->MFTRecordSize();
  //XXX check for mirror !
  this->add(0, mftNode);
}

MFTEntryManager::~MFTEntryManager()
{
  std::map<uint64_t, MFTEntryInfo* >::const_iterator entry = this->__entries.begin();
  for (; entry != this->__entries.end(); ++entry)
     delete ((*entry).second);
}

/**
 *  Number of MFT Entry
 */ 
uint64_t MFTEntryManager::entryCount(void) const
{
  return (this->__numberOfEntry);
}

/**
 *  Is MFEntryNode exist for this MFT id
 */
bool    MFTEntryManager::exist(uint64_t id) const
{
  std::map<uint64_t, MFTEntryInfo*>::const_iterator entry = this->__entries.find(id);
  if (entry != this->__entries.end()) //if node exist
  {
    if ((*entry).second == NULL)
       return (false);
    return (true);
  }
  return (false);
}

/**
 *  Add a node to an MFTEntry
 */
bool    MFTEntryManager::add(uint64_t id, MFTNode* node)
{
  if (this->exist(id) == false)
  {
    if (this->exist(id))
      std::cout << "CHELOU add " << std::endl;
    this->__entries[id] = new MFTEntryInfo(node);
    //this->addChildId(id, node); //XXX pour l instant on link avec les id 
  }
  return (true);
}

/**
 *  Add a child ID  
 */
bool    MFTEntryManager::add(uint64_t id, uint64_t childId)
{
//sanitaze !
  if (this->exist(id) == false)
  {
    std::cout << "Adding to a non-existent entry " << id << " child " << childId << std::endl;
  }
  else
    this->__entries[id]->childrenId.push_back(childId);

  return (true);
}

/**
 *  Return Node corresponding to MFT id or NULL 
 */
MFTNode*  MFTEntryManager::node(uint64_t id) const
{
  std::map<uint64_t, MFTEntryInfo*>::const_iterator entry = this->__entries.find(id);
  if (entry != this->__entries.end()) //if node exisit
  {
    MFTEntryInfo* info = (*entry).second;
    if (info)
      return (info->node);
  }
  return (NULL);
}

/**
 * Get all indexes for node and add it to MFT id children list 
 */
bool    MFTEntryManager::addChildId(uint64_t nodeId, MFTNode* node)
{
  std::vector<IndexEntry> indexes = node->indexes();
  std::vector<IndexEntry>::iterator index = indexes.begin();
  if (indexes.size() == 0)
  {
    indexes.clear();
    return (true);
  }
 
  for (; index != indexes.end(); ++index)
  {
    uint64_t entryId = (*index).mftEntryId();
    if (entryId == 0) //end of list
      continue;
    this->add(nodeId, entryId);
  }

  if (this->exist(nodeId))
  {
    this->__entries[nodeId]->childrenId.sort();
    this->__entries[nodeId]->childrenId.unique();
  }
  else
   std::cout << "CHELOU ADD CHILD" << std::endl;
  return (true);
}

/**
 *  This parse entry id child id and childNode to Node childrens
 */

bool    MFTEntryManager::addChild(uint64_t nodeId)
{
  Node* node = this->node(nodeId);
  
  if (node == NULL) 
  {
    //std::cout << "parent " << nodeId << " not found !" << std::endl;
    return (false);
  }
                                        //check if null / size d abord ? ou allocate au debut la bonne taille ? 
  MFTEntryInfo* info =  this->__entries[nodeId];
  std::list<uint64_t>::iterator childId = info->childrenId.begin();
//XXX this algo is fucked up avec les unnalocated au moins
//car si y a un unallocated qui etait link a une liste de fichier
//il va reclamer c node et comme elle ont pas de parent elle vont etre linker
//a un parent mais pas relink ds la partie relink donc elle serot linker au movais parent !
// si non forcer double relinking
  //XXX check sequence en + ? 

  if (info->childrenId.size() == 0)
    return (false);
  for (; childId != info->childrenId.end(); ++childId)
  {
    if (*childId == 0) //end of list
      continue;
    Node* child = this->node(*childId);
    if (child)
     node->addChild(child);
    else
      std::cout << "Child not ofund !" << std::endl;
  }
  return (true);
}

/**
 *  Check for infinite loop inChildren childid with parent id
 */
void    MFTEntryManager::inChildren(uint64_t id, uint64_t childId)
{
  if (!this->exist(childId))  //XXX a mettre aileurs suffisant ? 
    return ;
  MFTEntryInfo* info = this->__entries[childId];
  if (info->childrenId.size() == 0)
    return ;

  std::list<uint64_t>::const_iterator subchild = info->childrenId.begin();
  for (; subchild != info->childrenId.end(); ++subchild)
  {
    if (id == *subchild)
    {
      info->childrenId.remove(*subchild);
      break;
    }
    else
      this->inChildren(id, *subchild);
  }
}
/**
 *  Check for infinite directory loop in each entries
 */ 
void    MFTEntryManager::childrenSanitaze(void)
{
  std::map<uint64_t, MFTEntryInfo* >::iterator  entry = this->__entries.begin();
  for (; entry != this->__entries.end(); entry++)
     this->inChildren(entry->first, entry->first);
}

/*
 *  Create all MFT Entry 
 */
void    MFTEntryManager::initEntries(void)
{
  std::ostringstream nMFTStream;
  nMFTStream  << std::string("Found ") << this->__numberOfEntry <<  std::string(" MFT entry") << endl;
  this->__ntfs->setStateInfo(nMFTStream.str());

  uint32_t mftRecordSize = this->__ntfs->bootSectorNode()->MFTRecordSize();

  for(uint64_t id = 0; id < this->__numberOfEntry; ++id)
  {
    if (id % 10000 == 0)
    {
      std::ostringstream cMFTStream;
      cMFTStream << "Parsing " << id << "/" << this->__numberOfEntry;
      std::cout << cMFTStream.str() << std::endl;
      this->__ntfs->setStateInfo(cMFTStream.str());
    }
    try 
    {
      if (this->__entries[id] == NULL)
      {
        MFTNode* currentMFTNode = new MFTNode(this->__ntfs, this->__masterMFTNode, NULL, id * mftRecordSize); 
        this->add(id, currentMFTNode);
      }
    }
    catch (std::string& error)
    {
      std::cout << "Can't create MFTNode" << id << " error: " << error << std::endl;
    }
  }
}

/**
 *  Create node from id
 */
MFTNode*   MFTEntryManager::create(uint64_t id)
{
  uint32_t mftRecordSize = this->__ntfs->bootSectorNode()->MFTRecordSize();
  MFTNode* node = new MFTNode(this->__ntfs, this->__masterMFTNode, NULL, id * mftRecordSize);

  return (node);
}

/*
 *  Link node to parent
 */  
void    MFTEntryManager::linkEntries(void)
{
  std::cout << "linking entries" << std::endl;
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

/**
 *   Link orphans entries (MFTNode with a NULL parent)
 */

void    MFTEntryManager::linkOrphanEntries(void)
{
  std::cout << "linking orphans" << std::endl;
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
              ////std::cout << "PARENT " << mftNode->name() << " and parent  " << parent->name() << " Have != seq  " << std::endl;
             /////XXX also can if check is mftNode.isDirectory() // car si non c bien reecrit c chelou         
             ////par ex les images de meg0 rien a voir     
             this->__ntfs->orphansNode()->addChild(mftNode);
             ////std::cout << "Seq is different " << mftNode->name() <<  ", " << parent->name() << std::endl;
          }
          else 
          {
            parent->addChild(mftNode);
             ////std::cout << "aprent and son sequence ok " << std::endl;
            ////delete fileName /dellte for in *attribute .. continue 
            ////std::cout << "oprhan " << mftNode->name() << " found in existing parent " << parent->name() << std::endl;
          }
        }
        ////else 
        ////std::cout << "orphan with parent found but parent not found ! " << parentId << std::endl;
       
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

/*
 *
 */

void    MFTEntryManager::linkUnallocated(void)
{
  std::cout << "linking unallocated " << std::endl;
  this->__ntfs->rootDirectoryNode()->addChild(new Unallocated(this->__ntfs));
}

Unallocated::Unallocated(NTFS* ntfs) : Node("FreeSpace", 0, NULL, ntfs), __ntfs(ntfs)
{
  std::vector<Range> ranges = this->ranges();
  std::vector<Range>::const_iterator range = ranges.begin();

  uint64_t size = 0;
  for (; range != ranges.end(); ++range)
    size += (1 + (*range).end() - (*range).start()) * this->__ntfs->bootSectorNode()->clusterSize();
  this->setSize(size);
}

std::vector<Range> Unallocated::ranges(void)
{
  std::vector<Range> ranges;
  MFTEntryManager* mftManager = this->__ntfs->mftManager();
  if (mftManager == NULL)
    throw std::string("MFT Manager is null");

  MFTNode* bitmapNode = mftManager->node(6); //$BITMAP_FILE_ID
  if (!bitmapNode)
    return (ranges);

  std::vector<MFTAttribute*> attributes = bitmapNode->mftEntryNode()->MFTAttributesType($DATA);
  std::vector<MFTAttribute*>::iterator  attribute = attributes.begin();

  MFTAttributeContent* content = (*attribute)->content();
  if (content) 
  {
    Bitmap* bitmap = static_cast<Bitmap*>(content);
    ranges = bitmap->unallocatedRanges();
    delete content;
  }
  for (; attribute != attributes.end(); ++attribute)
    delete (*attribute);

  return (ranges);
}

void    Unallocated::fileMapping(FileMapping* fm)
{
  std::vector<Range> ranges = this->ranges();
  std::vector<Range>::const_iterator range = ranges.begin();
  uint64_t offset = 0;
  uint64_t clusterSize = this->__ntfs->bootSectorNode()->clusterSize();

  for (; range != ranges.end(); ++range)
  {
    //XXXX XXX  1 - 1 pour cluster de 1 
    fm->push(offset , (1 + (*range).end() - (*range).start()) * clusterSize, this->__ntfs->fsNode(), (*range).start() * clusterSize);
    offset += (1 + (*range).end() - (*range).start()) * clusterSize;
  }
}
