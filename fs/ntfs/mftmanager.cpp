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
#include "unallocated.hpp"
#include "attributes/mftattributecontenttype.hpp"

/**
 *  MFTEntryManager
 */
MFTEntryManager::MFTEntryManager(Destruct::DStruct* dstruct) : DCppObject<MFTEntryManager>(dstruct), __ntfs(NULL), __masterMFTNode(NULL), __masterMFTOffset(0), __numberOfEntry(0)
{
  //CppClass haha !this->init();
}

MFTEntryManager::MFTEntryManager(Destruct::DStruct* dstruct, Destruct::DValue const& args) : DCppObject<MFTEntryManager>(dstruct, args), __ntfs(NULL), __masterMFTNode(NULL), __masterMFTOffset(0), __numberOfEntry(0)
{
 // this->init();
}

MFTEntryManager::~MFTEntryManager()
{
  std::map<uint64_t, MFTEntryInfo* >::const_iterator entry = this->__entries.begin();
  for (; entry != this->__entries.end(); ++entry)
     delete ((*entry).second);
}

void    MFTEntryManager::init(NTFS* ntfs)
{
  //XXX check for mirror !
  this->__ntfs = ntfs;
  this->__masterMFTOffset = this->__ntfs->bootSectorNode()->MFTLogicalClusterNumber() * this->__ntfs->bootSectorNode()->clusterSize();
  this->createFromOffset(this->__masterMFTOffset, this->__ntfs->fsNode(), 0);
  this->__masterMFTNode = this->node(0);
  if (this->__masterMFTNode == NULL)
    throw std::string("Can't create master MFT entry"); //try mirror
  if (this->__ntfs->bootSectorNode()->MFTRecordSize() == 0)
    throw std::string("Can't read MFT Record : BootSector MFT Record size is 0");
  this->__numberOfEntry = this->__masterMFTNode->size() / this->__ntfs->bootSectorNode()->MFTRecordSize();
}


/**
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
      return (info->entryNode());
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
MFTEntryInfo*   MFTEntryManager::create(uint64_t id)
{
  MFTEntryInfo* mftEntryInfo = NULL;
  uint32_t mftRecordSize = this->__ntfs->bootSectorNode()->MFTRecordSize();
  if (this->__masterMFTNode == NULL)
     mftEntryInfo = this->createFromOffset(this->__masterMFTOffset + (id * mftRecordSize),  this->__ntfs->fsNode(), id); //this happen when master MFT use attributelist for is $DATA content (very large and/or very fragmented MFT)
  else
    mftEntryInfo = this->createFromOffset(id * mftRecordSize, this->__masterMFTNode, id);
  return (mftEntryInfo);
}

/**
 *   Create an MFTEntryNode and all it's derived MFTNode 
 *   then register in the manager if id != -1
 *   Return MFTNEntryInfo* or throw error  if id -1 MFTEntryNode* is not registred so must
 *   be deleted by caller
 */ 
MFTEntryInfo*  MFTEntryManager::createFromOffset(uint64_t offset, Node* fsNode, int64_t id)
{
  /* MFTEntryNode throw on error */
  MFTEntryNode* mftEntryNode = new MFTEntryNode(this->__ntfs, fsNode, offset, std::string("MFTEntry"), NULL);
  if (mftEntryNode == NULL)
    throw std::string("Can't allocate MFTEntryNode");

  MFTEntryInfo* mftEntryInfo = NULL; 
  if (id == -1)
    mftEntryInfo = new MFTEntryInfo(mftEntryNode);
  else 
  {
    if (this->exist(id))
      mftEntryInfo = this->__entries[id]; //XXX possibilite d utiliser la base deserializer alors ?
    else
    {
      mftEntryInfo = new MFTEntryInfo(mftEntryNode);
      this->__entries[id] = mftEntryInfo;
    }
  }

  /* 
   * Get node base name
   */
  std::string name = mftEntryNode->findName();
  if (name == "")
  {
    std::ostringstream sname; 
    sname << "Unknown-" << offset;
    name = sname.str();
  } //XXX serializer le nom trouver pour la node ? 
  /* 
   * Set node Size & attributes offset for filemaping
   */
  std::map<std::string, MappingAttributesInfo > mapDataInfo;
 
  std::vector<MFTAttribute*> datas = mftEntryNode->data();
  std::vector<MFTAttribute*>::iterator data = datas.begin();
  for (; data != datas.end(); ++data)
  {
    std::string finalName = name;
    if ((*data)->name() != "")
      finalName += ":" + (*data)->name();

    if (mapDataInfo.find(finalName) == mapDataInfo.end())//avoid to push all attributes list with same name when fragmented
    {
      mapDataInfo[finalName].size = (*data)->contentSize();
      mapDataInfo[finalName].compressed = (*data)->isCompressed();
    }

    //serializable voir plus haut offset, name etc...
    mapDataInfo[finalName].mappingAttributes.push_back(MappingAttributes((*data)->offset(), (*data)->mftEntryNode()));
    
    delete (*data);
  } //XXX sauvegarde ca ?
  
  /*
   *  No data attribute is found but an MFTEntry can represent a directory without a $DATA Attribute
   */
  if (datas.size() == 0) //handle directory without data
  {
    MFTNode* mftNode = new MFTNode(name, __ntfs, mftEntryNode, mftEntryNode->isDirectory(), mftEntryNode->isUsed());

    mftEntryInfo->node = mftNode;
    mftEntryInfo->nodes.push_back(mftNode);
  }
  else
  {
    std::map<std::string, MappingAttributesInfo >::iterator info = mapDataInfo.begin();
    for (; info != mapDataInfo.end(); ++info)
    {
      MFTNode* mftNode = new MFTNode(((*info)).first, __ntfs, mftEntryNode, mftEntryNode->isDirectory(), mftEntryNode->isUsed());
      (*info).second.mappingAttributes.unique();//pass mapping info in constructor ?
      mftNode->setMappingAttributes((*info).second);

      if (((*info).first) == name && (mftEntryInfo->node == NULL))
        mftEntryInfo->node = mftNode;
      mftEntryInfo->nodes.push_back(mftNode); 

    }
  }
  return (mftEntryInfo);
}


Destruct::DValue         MFTEntryManager::saveEntries(void) const
{
  Destruct::Destruct&   destruct = Destruct::Destruct::instance();
  Destruct::DObject*    dentries = destruct.generate("DMapUInt64Object");

  std::map<uint64_t, MFTEntryInfo*>::const_iterator i = this->__entries.begin();
  for (; i != this->__entries.end(); ++i) 
  {
    Destruct::DObject* item = dentries->call("newItem").get<Destruct::DObject*>(); 
    item->setValue("key", Destruct::RealValue<DUInt64>(i->first));
    item->setValue("value", Destruct::RealValue<Destruct::DObject* >((i->second)->save()));
    dentries->call("setItem", Destruct::RealValue<Destruct::DObject*>(item));
  }

  return (Destruct::RealValue<Destruct::DObject*>(dentries));
}

void                    MFTEntryManager::loadEntries(Destruct::DValue const& entries, Node* fsNode)
{
  std::cout << "MFTEntryManager::loadEntries(DValue entries, Node* fsNode)" << std::endl;

  Destruct::DObject* dentries = entries.get<Destruct::DObject* >();
  Destruct::DObject* iterator = dentries->call("iterator").get<Destruct::DObject* >();

  for (; iterator->call("isDone").get<DUInt8>(); iterator->call("nextItem"))
  {
    Destruct::DValue key = iterator->call("currentItem");
    Destruct::DObject* value = dentries->call("get", key).get<Destruct::DObject*>();
    std::cout << "Get Key Value in entries map " << key.asUnicodeString() << ":" << value->instanceOf()->name() << std::endl;
  }

  std::cout << "MFTEntryManager::loadEntries return " << std::endl;
}


/*
void    MFTEntryManager::loadEntries(Destruct::DObject* entries, Node* fsNode)
{
  int64_t id = 0;
  uint64_t idCount = entries->call("size").get<DUInt64>();

  for (; id < idCount; ++id)
  {
     DObject* entryInfo = entries->call("get", Destruct::RealValue<DUInt64>(id));
     
     uint64_t offset = entryInfo->mftEntryNode->offset;
     std::string mftNodeName = entryInfo->mftEntryNode->name
     MFTEntryNode* mftEntryNode = new MFTEntryNode(this->__ntfs, fsNode, offset, "MFTEntry", NULL); 

     mftEntryInfo = MFTEntryInfo(mftEntryNode);
     this->__entries[id] = mftEntryInfo;

     * 
   * Set node Size & attributes offset for filemaping
   *
    datas //XXX ? a recup car ca c lent on fait les read de $data
    if  mftEntryInfo.datas()  // XXX XXX tous est ok sauf ici ?
    {
      mftNode=  new MFTNode(__ntfs, mftEntryNode) //ici ca fait du read a chaque fois c quand meme cet partie qui est lente ! donc voir si ca vaux le coup au final ! 
      mftNode->setName(name)
      if mftEntryNode->isUsed()
        ...
      if mftEntry->isDir()
        ...
      else
        ...
      mftEntryNode->node = mftNode
      mftEntryNode->nodes.push_back(mftNode);
      return mftEntryInfo
    }
    else
    {
      for (mapDataInfo) #XXX ???
      {  
       mftNode = new MFTNode(nftds, mftEntryNode)
       if entryInfo->mftNode->name == mapDataInfo.name
        mftEntryInfo->mftNode = mftnode
       mftENtryInfo.nodes.push_back(mftNode)
        
       mftNode->setValue() //is dir is deleted mapping attriubte -> XXX XXX en faite y a que ca a save est on est bon :) 
       //les mettre ds une list et go !

      // mftNode = new MFTNode(...)
      }

    } 

  }



} */

/**
 *   Link orphans entries (MFTNode with a NULL parent) //in fatct link all entry  if we don't use index
 */
void    MFTEntryManager::linkOrphanEntries(void)
{
  this->__ntfs->setStateInfo("Linking orphans");
  for (uint64_t id = 0; id < this->__numberOfEntry; ++id)
  {
    MFTEntryInfo* entryInfo = this->__entries[id];
    std::list<MFTNode*>::const_iterator mftNode = entryInfo->nodes.begin();
    for (; mftNode != entryInfo->nodes.end(); ++mftNode)
    {
      if (((*mftNode) == NULL) || ((*mftNode)->parent()))
        continue;
      std::vector<MFTAttribute* > attributes;
      attributes = (*mftNode)->mftEntryNode()->findMFTAttributes($FILE_NAME); //must check for all ADS too
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
            this->__ntfs->orphansNode()->addChild(*mftNode);
          else 
            parent->addChild(*mftNode);
        }
        delete fileName;
      }
      else
        this->__ntfs->orphansNode()->addChild(*mftNode);
   
      for (; attribute != attributes.end(); ++attribute)
        delete (*attribute);
    }
  }
}

/**
 * Create unallocated node containing unused cluster 
 * Must check for index and relink files too XXX
 */
Unallocated* MFTEntryManager::createUnallocated(void)
{
  Unallocated* unallocated = new Unallocated(this->__ntfs);
  this->__ntfs->rootDirectoryNode()->addChild(unallocated);
  return (unallocated);
}

void    MFTEntryManager::searchUnallocated(Unallocated* unallocated)
{
  uint64_t mftRecordSize = this->__ntfs->bootSectorNode()->MFTRecordSize(); 
  uint64_t clusterSize = this->__ntfs->bootSectorNode()->clusterSize(); 

  this->__ntfs->setStateInfo("Getting unallocated blocks list");
  std::vector<Range> ranges = unallocated->ranges();
  std::vector<Range>::const_iterator range = ranges.begin();

  uint32_t signature;
  uint64_t parsed = 0;
  VFile* fsFile = this->__ntfs->fsNode()->open();

  this->__unallocatedOffset = Destruct::Destruct::instance().generate("DVectorUInt64");

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
        static_cast<Destruct::DObject*>(this->__unallocatedOffset)->call("push", Destruct::RealValue<DUInt64>(offset));
    }
  }
  uint64_t recovered = this->linkUnallocated(unallocated);
  std::ostringstream state;
  state << "Recovered " << recovered << "/" << parsed;
  this->__ntfs->setStateInfo(state.str());

  delete fsFile;
}

uint64_t MFTEntryManager::linkUnallocated(Unallocated* unallocated)
{
  uint64_t recovered = 0;

  Destruct::DObject* vector = this->__unallocatedOffset;
  Node*  fsNode = this->__ntfs->fsNode();

  DUInt64 count = vector->call("size").get<DUInt64>();
  for (DUInt64 index = 0; index < count; index++)
  {
     try
     {
       DUInt64 offset = vector->call("get", Destruct::RealValue<DUInt64>(index)).get<DUInt64>();
       MFTEntryInfo* entryInfo = this->createFromOffset(offset, fsNode, -1);
       std::list<MFTNode* >::const_iterator mftNode = entryInfo->nodes.begin();
       for ( ; mftNode != entryInfo->nodes.end(); ++mftNode)
       {
         if ((*mftNode))
           unallocated->addChild((*mftNode)); 
       }
       recovered++;
       delete entryInfo;
     }
     catch (...)
     {
     }    
  }
  return (recovered);
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
        //std::string error("Can't create VLink for repars point : " + printName);
        //std::cout << error << std::endl;
      }
      delete reparsePoint;
    }
    for (; attribute != reparses.end(); ++attribute)
      delete (*attribute);
  }
  return (NULL);
}

MFTNode*        MFTEntryManager::masterMFTNode(void) const
{
  return (this->__masterMFTNode);
}

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
MFTEntryInfo::MFTEntryInfo(MFTEntryNode* entryNode) : id(0), node(NULL), __entryNode(entryNode)
{
}

MFTEntryInfo::~MFTEntryInfo()
{
//delete node & unlink
}

MFTEntryNode*           MFTEntryInfo::entryNode(void) const
{
  return (this->__entryNode);
}

Destruct::DObject*      MFTEntryInfo::save(void) const
{
  Destruct::Destruct& destruct = Destruct::Destruct::instance();
  Destruct::DObject* dmftEntry = destruct.generate("MFTEntryInfo");
  Destruct::DObject* dnodes = destruct.generate("DVectorObject");

  //++nodes; HEIN ???? c surcharger ou ca ?

  dmftEntry->setValue("id", Destruct::RealValue<DUInt64>(this->id));
  if (this->node)
    dmftEntry->setValue("node", Destruct::RealValue<Destruct::DObject*>(this->node->save()));
  for (std::list<MFTNode*>::const_iterator mftNode = this->nodes.begin(); mftNode != this->nodes.end(); ++mftNode)
  {
    if (*mftNode)
      dnodes->call("push", Destruct::RealValue<Destruct::DObject*>((*mftNode)->save()));
  }
  dmftEntry->setValue("nodes", Destruct::RealValue<Destruct::DObject*>(dnodes)); 
  dmftEntry->setValue("entryNode", Destruct::RealValue<DUInt64>(this->__entryNode->offset()));
  ///XXX MFTid List ? ?? not used yet  
 
  return (dmftEntry);
}
