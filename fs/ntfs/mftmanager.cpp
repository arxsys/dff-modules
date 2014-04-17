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
#include "ntfsopt.hpp"
#include "mftnode.hpp"
#include "bootsector.hpp"
#include "mftattributecontenttype.hpp"

/**
 *  MFTEntryInfo
 */
MFTEntryInfo::MFTEntryInfo(MFTNode* _node) : id(0), node(_node)
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
    this->__entries[id] = new MFTEntryInfo(node);
    //this->addChildId(id, node);
  }
  return (true);
}

/**
 *  Return Node corresponding to MFT id or NULL 
 */
MFTNode*  MFTEntryManager::node(uint64_t id) const
{
  std::map<uint64_t, MFTEntryInfo*>::const_iterator entry = this->__entries.find(id);
  if (entry != this->__entries.end())
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
    uint16_t sequence = (*index).sequence();
    if (entryId == 0)
      continue;

    if (entryId == 8290)
      std::cout << "entry id found for " << nodeId << " " << entryId << " " << sequence << std::endl;
    this->__entries[nodeId]->childrenId.push_back(MFTId(entryId, sequence));
  }

  if (this->exist(nodeId))
  {
    this->__entries[nodeId]->childrenId.sort();
    this->__entries[nodeId]->childrenId.unique();
  }

  return (true);
}

/**
 *  This parse entry id child id and childNode to Node childrens
 */
bool    MFTEntryManager::addChild(uint64_t nodeId)
{
  MFTNode* node = this->node(nodeId);
  
  if (node == NULL) 
    return (false);
  
  MFTEntryInfo* info =  this->__entries[nodeId];
  std::list<MFTId>::iterator childId = info->childrenId.begin();

  if (info->childrenId.size() == 0)
    return (false);
  for (; childId != info->childrenId.end(); ++childId)
  {
    if ((*childId).id == 0)
      continue;
    MFTNode* child = this->node((*childId).id);
    if (child)
    {
      if ((*childId).sequence == node->mftEntryNode()->sequence())
      {
        if ((*childId).id == 8290)
          std::cout << "HELLO " <<  child->name() << " parent " << node->name() << std::endl;
        node->addChild(child);
      }
    }
  }
  return (true);
}

/**
 *  Check for infinite loop inChildren childid with parent id
 */
void    MFTEntryManager::inChildren(uint64_t id, uint64_t childId)
{
  if (!this->exist(childId))
    return ;
  MFTEntryInfo* info = this->__entries[childId];
  if (info->childrenId.size() == 0)
    return ;

  std::list<MFTId>::const_iterator subchild = info->childrenId.begin();
  for (; subchild != info->childrenId.end(); ++subchild)
  {
    if (id == (*subchild).id)
    {
      info->childrenId.remove((*subchild));
      break;
    }
    else
      this->inChildren(id, (*subchild).id);
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

/**
 *  Create node from id
 *  Can be used for indexallocation or others function that need node not yet created at init
 */
MFTNode*   MFTEntryManager::create(uint64_t id)
{
  uint32_t mftRecordSize = this->__ntfs->bootSectorNode()->MFTRecordSize();
  MFTNode* node = new MFTNode(this->__ntfs, this->__masterMFTNode, NULL, id * mftRecordSize);

  return (node);
}

/*
 *  Create all MFT Entry found in the main MFT 
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


/*
 *  Link node to parent
 */  
void    MFTEntryManager::linkEntries(void)
{
  //this->childrenSanitaze();
  //for(uint64_t id = 0; id < this->__numberOfEntry; ++id)
  //{
    //if (id % 1000 == 0)
      //std::cout << "linking node " << id << std::endl;
    //this->addChild(id); 
  //}
  /* mount root '.' as 'ntfs/root/' */
  MFTNode* rootMFT = this->node(5);
  if (rootMFT)
  {
    rootMFT->setName("root"); //replace '.'
    this->__ntfs->rootDirectoryNode()->addChild(rootMFT);
  }
}

/**
 *   Link orphans entries (MFTNode with a NULL parent)
 */
void    MFTEntryManager::linkOrphanEntries(void)
{
  this->__ntfs->setStateInfo("Linking orphans");
  for(uint64_t id = 0; id < this->__numberOfEntry; ++id)
  {
    MFTNode* mftNode = this->node(id);
 
    if (mftNode && (mftNode->parent() == NULL))
    {
      std::vector<MFTAttribute* > attributes = mftNode->mftEntryNode()->MFTAttributesType($FILE_NAME);
      std::vector<MFTAttribute* >::iterator attribute = attributes.begin();
      if (attributes.size())
      {
        FileName* fileName = dynamic_cast<FileName*>((*attribute)->content());
        uint64_t parentId = fileName->parentMFTEntryId();
        MFTNode* parent = this->node(parentId);

        if (parent)
        {
          if (fileName->parentSequence() != parent->mftEntryNode()->sequence())
             this->__ntfs->orphansNode()->addChild(mftNode);
          else 
            parent->addChild(mftNode);
        }
       
        delete fileName;
      }
      else
        this->__ntfs->orphansNode()->addChild(mftNode);
      for (; attribute != attributes.end(); ++attribute)
        delete (*attribute);
    }
  }
}

/*
 * Create unallocated node containing unused cluster 
 * Must check for index and relink files too XXX
 */

void    MFTEntryManager::linkUnallocated(void)
{
  Unallocated* unallocated = new Unallocated(this->__ntfs);
  this->__ntfs->rootDirectoryNode()->addChild(unallocated);

  if (this->__ntfs->opt()->recovery() == false)
    return ;

  uint64_t mftRecordSize = this->__ntfs->bootSectorNode()->MFTRecordSize(); 
  uint64_t clusterSize = this->__ntfs->bootSectorNode()->clusterSize(); 

  this->__ntfs->setStateInfo("Getting unallocated blocks list");
  std::vector<Range> ranges = unallocated->ranges();
  std::vector<Range>::const_iterator range = ranges.begin();

  uint32_t signature;
  uint64_t recovered = 0;
  uint64_t parsed = 0;
  Node*  fsNode = this->__ntfs->fsNode();
  VFile* fsFile = this->__ntfs->fsNode()->open();

  for (uint64_t rangeCount = 0; range != ranges.end(); ++range, ++rangeCount) 
  {
    std::ostringstream state;
    state << "Cheking unallocated range " << rangeCount << "/" << ranges.size();
    this->__ntfs->setStateInfo(state.str());

    for(uint64_t offset = (*range).start() * clusterSize; offset < ((*range).end() + 1) * clusterSize; offset += mftRecordSize)
    {
      parsed++;
      fsFile->seek(offset);
      fsFile->read(&signature, 4);
        
      if (signature == MFT_SIGNATURE_FILE)
      {
        try
        {
          MFTNode* entry = new MFTNode(this->__ntfs, fsNode, NULL, offset);
          unallocated->addChild(entry);
          recovered++;
        }
        catch(...)
        {
        }
      }
    }
  }
  std::ostringstream state;
  state << "Recovered " << recovered << "/" << parsed;
  this->__ntfs->setStateInfo(state.str());

  delete fsFile;
}


/**
 *  Unallocated Node
 */

Unallocated::Unallocated(NTFS* ntfs) : Node("FreeSpace", 0, NULL, ntfs), __ntfs(ntfs)
{
  this->__ranges = this->ranges();
  std::vector<Range>::const_iterator range = this->__ranges.begin();

  uint64_t size = 0;
  for (; range != this->__ranges.end(); ++range)
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
  std::vector<Range>::const_iterator range = this->__ranges.begin();
  uint64_t offset = 0;
  uint64_t clusterSize = this->__ntfs->bootSectorNode()->clusterSize();

  for (; range != this->__ranges.end(); ++range)
  {
    fm->push(offset , (1 + (*range).end() - (*range).start()) * clusterSize, this->__ntfs->fsNode(), (*range).start() * clusterSize);
    offset += (1 + (*range).end() - (*range).start()) * clusterSize;
  }
}
