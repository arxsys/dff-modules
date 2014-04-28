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

#include "vlink.hpp"

#include "mftmanager.hpp"
#include "ntfs.hpp"
#include "ntfsopt.hpp"
#include "mftnode.hpp"
#include "bootsector.hpp"
#include "mftattributecontenttype.hpp"
#include "unallocated.hpp"

/**
 *  MFTId
 */
MFTId::MFTId(uint64_t _id, uint16_t seq) : id(_id), sequence(seq) 
{
}

bool  MFTId::operator==(MFTId const& other)
{
  if ((other.id == this->id) && (other.sequence == this->sequence))
    return (true);
  return (false);
}

bool  MFTId::operator<(MFTId const& other)
{
  if (other.id < this->id)
    return (true);
  return (false);
}

/**
 *  MFTEntryInfo
 */
MFTEntryInfo::MFTEntryInfo() : id(0), node(NULL), entryNode(NULL)
{
}

MFTEntryInfo::~MFTEntryInfo()
{
//delete node & unlink
}

/**
 *  MFTEntryManager
 */
MFTEntryManager::MFTEntryManager(NTFS* ntfs) : __ntfs(ntfs) //, __masterMFTNode(mftNode)
{
  //XXX check for mirror !
  this->createFromOffset(ntfs->bootSectorNode()->MFTLogicalClusterNumber() * ntfs->bootSectorNode()->clusterSize(), ntfs->fsNode(), 0);
  this->__masterMFTNode = this->node(0); //or entrynode
  if (this->__masterMFTNode == NULL)
    throw std::string("Can't create master MFT entry"); //try mirror 
  this->__numberOfEntry = this->__masterMFTNode->size() / this->__ntfs->bootSectorNode()->MFTRecordSize();
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
 *  Return EntryNode corresponding to MFT id or NULL 
 */
MFTEntryNode*  MFTEntryManager::entryNode(uint64_t id) const
{
  std::map<uint64_t, MFTEntryInfo*>::const_iterator entry = this->__entries.find(id);
  if (entry != this->__entries.end())
  {
    MFTEntryInfo* info = (*entry).second;
    if (info)
      return (info->entryNode);
  }
  return (NULL);
}

/**
 * Get all indexes for node and add it to MFT id children list 
 */
bool    MFTEntryManager::addChildId(uint64_t nodeId, MFTNode* node)
{
  std::vector<IndexEntry> indexes = node->mftEntryNode()->indexes();
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
        node->addChild(child);
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
MFTNode*   MFTEntryManager::create(uint64_t id) //XXX XXX create only : not added in bases ?
{
  uint32_t mftRecordSize = this->__ntfs->bootSectorNode()->MFTRecordSize();
  MFTNode* mftNode = this->createFromOffset(id * mftRecordSize, this->__masterMFTNode, id);
  return (mftNode);
}

MFTNode*  MFTEntryManager::createFromOffset(uint64_t offset, Node* fsNode, int64_t id)
{
  MFTEntryNode* mftEntryNode = new MFTEntryNode(this->__ntfs, fsNode, offset, std::string("MFTEntry"), NULL);
  //if (this->exist(id) == false)
  //{
  MFTEntryInfo* mftEntryInfo = new MFTEntryInfo;
  if (id != -1)
  {
    this->__entries[id] = mftEntryInfo;
    mftEntryInfo->entryNode = mftEntryNode;
  }
  //} //XXX

  if (mftEntryNode == NULL)
  {
    //throw Error ?
    //delete mftNode; null
    std::cout << "Error creating node at offset " << offset << " no mftEntry " << std::endl;
    return (NULL); //ret NULL car peut rien faire finalement !
  }
  /* 
   * get node base name
   */
  std::string name = mftEntryNode->findName();
  if (name == "")
  {
    std::ostringstream sname; 
    sname << "Unknown-" << offset;
    name = sname.str();
  }
  /* 
   * Set node Size & attributes offset for filemaping
   */
  std::map<std::string, MappingAttributesInfo > map;
  MFTNode* tmp = NULL; //for compat only
 
  std::vector<MFTAttribute*> datas = mftEntryNode->data();
  std::vector<MFTAttribute*>::iterator data = datas.begin();
  for (; data != datas.end(); ++data)
  {
    std::string finalName = name;
    if ((*data)->name() != "")
      finalName += ":" + (*data)->name();
    ///XXX XXX check if already set car je c pas si ds les attribute list y a aussi la bonne size et aussi compressed recopier
    map[finalName].size = (*data)->contentSize();
    map[finalName].compressed = (*data)->isCompressed();
    map[finalName].mappingAttributes.push_back(MappingAttributes((*data)->offset(), (*data)->mftEntryNode()));
    delete (*data);
  }
  if (datas.size() == 0) //ex direectory etc : have name but no data || handle no name no data also !
  {
    MFTNode* mftNode = new MFTNode(__ntfs, mftEntryNode);
    if (id != -1)
      mftEntryInfo->nodes.push_back(mftNode);
    tmp = mftNode;
    if (!mftEntryNode->isUsed()) //not sufficient need $BITMAP ? check & compare
      tmp->setDeleted();
    if (mftEntryNode->isDirectory())
      tmp->setDir();
    else
      tmp->setFile();
    tmp->setName(name);
  }
  else
  {
  //mftEntryNode->updateState(); //?
    std::map<std::string, MappingAttributesInfo >::iterator info = map.begin();
    for (; info != map.end(); ++info)
    {
      MFTNode* mftNode = new MFTNode(__ntfs, mftEntryNode); //get mappingInfo at construction ?
      if (id != -1)
        mftEntryInfo->nodes.push_back(mftNode);

      if ((*info).first == name)
        tmp = mftNode;
      else //XXX XXX fix temporaire 
      {
       if (tmp)
         tmp->addChild(mftNode);
      }
      
      if (tmp == NULL)
        tmp = mftNode;
      (*info).second.mappingAttributes.unique();
      mftNode->setMappingAttributes((*info).second);
      if (!mftEntryNode->isUsed()) //not sufficient need $BITMAP ? check & compare
        mftNode->setDeleted();
      if (mftEntryNode->isDirectory())
        mftNode->setDir();
      else
        mftNode->setFile();
      mftNode->setName((*info).first);
     //XXX delete MFTNode ??
    }
  }
  //XXX link ads ! 
  if (id != -1)
    mftEntryInfo->node = tmp;
  return (tmp); //XXX return main mft ? 
}

/*
 *  Create all MFT Entry found in the main MFT 
 */
void    MFTEntryManager::initEntries(void)
{
  std::ostringstream stateInfo;
  stateInfo << std::string("Found ") << this->__numberOfEntry <<  std::string(" MFT entry") << endl;
  this->__ntfs->setStateInfo(stateInfo.str());

  for(uint64_t id = 0; id < this->__numberOfEntry; ++id)
  {
    if (id % 10000 == 0)
    {
      std::ostringstream stateInfo;
      stateInfo << "Parsing " << id << "/" << this->__numberOfEntry;
      this->__ntfs->setStateInfo(stateInfo.str());
    }
    try 
    {
      if (this->__entries[id] == NULL)
        this->create(id);
    }
    catch (std::string& error)
    {
      std::cout << "Can't create MFTNode" << id << " error: " << error << std::endl;
    }
  }
}


/**
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
      std::vector<MFTAttribute* > attributes = mftNode->mftEntryNode()->findMFTAttributes($FILE_NAME);
      std::vector<MFTAttribute* >::iterator attribute = attributes.begin();
      if (attributes.size())
      {
        FileName* fileName = dynamic_cast<FileName*>((*attribute)->content());
        if (fileName == NULL)
          throw std::string("MFTEntryManager attribute content can't cast to $FILE_NAME"); 

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

/**
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
          MFTNode* entry = this->createFromOffset(offset, fsNode, -1);
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
 *  Create a VLink to reparse point if path is found and return VLink
 *  else return NULL
 */
Node*  MFTEntryManager::mapLink(MFTNode* node) const
{
  MFTEntryNode* mftEntryNode = node->mftEntryNode();
  if (!mftEntryNode)
    return (NULL);

  MFTAttributes reparses = mftEntryNode->findMFTAttributes($REPARSE_POINT);
  if (reparses.size())
  {
    MFTAttributes::iterator attribute = reparses.begin();
    MFTAttributeContent* content = (*attribute)->content();

    ReparsePoint* reparsePoint = dynamic_cast<ReparsePoint* >(content);
    if (reparsePoint)
    {
      std::string driveName = this->__ntfs->opt()->driveName();
      std::string printName = reparsePoint->print();

      if (driveName == printName.substr(0, 2))
      {
        std::string path = printName.substr(3); //chomp first '\'
        Node* nodeToLink = this->__ntfs->rootDirectoryNode();
        size_t pathPos = path.find("\\");
        std::string childName = "root";
        while (true)
        {
          std::vector<Node* > children = nodeToLink->children();
          std::vector<Node* >::iterator child = children.begin(); 
          if (children.size() == 0)
            break;
          for (; child != children.end() ;++child) 
          {
            if ((*child)->name() == childName)
            {
              nodeToLink = (*child);
              if (childName == path)
              {
                VLink* vlink = new VLink(nodeToLink, node);
                delete reparsePoint;
                for (; attribute != reparses.end(); ++attribute)
                  delete (*attribute);
                return (vlink); //XXX ret vlink
              }
              break;
            }
          }
          if (child == children.end())
            break;
          if (childName == path)
             break; //avoid invfinite loop
          pathPos = path.find("\\");
          if (pathPos == std::string::npos) //end link to 
            childName = path;
          else
          {
            childName = path.substr(0 , pathPos);
            path = path.substr(pathPos + 1);
          }
        }
        std::string error("Can't link create VLink for repars point : " + printName);
        std::cout << error << std::endl;
      }
      delete reparsePoint;
    }
    for (; attribute != reparses.end(); ++attribute)
      delete (*attribute);
  }
  return (NULL);
}

/**
 *  Search for all MFTNode with reparse point
 *  and try to create vlink from the node to the reparse point 
 */
void   MFTEntryManager::linkReparsePoint(void) const
{
  //sort by path to avoid dead link 
  //ex : Users -> vlink Users -> app/data -> vlink ie ...
  //resolve first ? 
  //handle vlink to directory in gui 
  //remove mftnode ?
  this->__ntfs->setStateInfo("Linking reparse point");
  std::map<uint64_t, MFTEntryInfo*>::const_iterator entry = this->__entries.begin();
  for (; entry != this->__entries.end(); ++entry)
  {
    MFTNode* mftNode = entry->second->node;
    if (mftNode)
      this->mapLink(mftNode);
  }
}
