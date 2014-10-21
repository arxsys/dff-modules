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
#include "bootsector.hpp"
#include "ntfsopt.hpp"
#include "mftnode.hpp"
#include "mftentrynode.hpp"
#include "unallocated.hpp"
#include "mftentryinfo.hpp"
#include "attributes/mftattributecontenttype.hpp"

#include "ntfs_common.hpp"

using namespace Destruct;

/**
 *  MFTEntryManager
 */
MFTEntryManager::MFTEntryManager(DStruct* dstruct) : DCppObject<MFTEntryManager>(dstruct), __ntfs(NULL), __masterDataNode(NULL), __masterMFTOffset(0), __numberOfEntry(0)
{
  //CppClass haha !this->init();
}

MFTEntryManager::MFTEntryManager(DStruct* dstruct, DValue const& args) : DCppObject<MFTEntryManager>(dstruct, args), __ntfs(NULL), __masterDataNode(NULL), __masterMFTOffset(0), __numberOfEntry(0)
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
  this->__masterDataNode = this->node(0);
  if (this->__masterDataNode == NULL)
    throw std::string("Can't create master MFT entry"); //try mirror
  if (this->__ntfs->bootSectorNode()->MFTRecordSize() == 0)
    throw std::string("Can't read MFT Record : BootSector MFT Record size is 0");
  this->__numberOfEntry = this->__masterDataNode->size() / this->__ntfs->bootSectorNode()->MFTRecordSize();
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
      std::cout << "Can't create DataNode" << id << " error: " << error << std::endl;
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
  DataNode* rootMFT = this->node(5);
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
DataNode*  MFTEntryManager::node(uint64_t id) const
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
bool    MFTEntryManager::addChildId(uint64_t nodeId, DataNode* node)
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
  DataNode* node = this->node(nodeId);
  
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
    DataNode* child = this->node((*childId).id);
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
void   MFTEntryManager::create(uint64_t id)
{
  uint32_t mftRecordSize = this->__ntfs->bootSectorNode()->MFTRecordSize();
  if (this->__masterDataNode == NULL)
    this->createFromOffset(this->__masterMFTOffset + (id * mftRecordSize),  this->__ntfs->fsNode(), id); //this happen when master MFT use attributelist for is $DATA content (very large and/or very fragmented MFT)
  else
    this->createFromOffset(id * mftRecordSize, this->__masterDataNode, id);
}

/**
 *   Create an MFTEntryNode and all it's derived DataNode 
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
    DataNode* dataNode = new DataNode(name, __ntfs, mftEntryNode, mftEntryNode->isDirectory(), mftEntryNode->isUsed());

    mftEntryInfo->node = dataNode;
    mftEntryInfo->nodes.push_back(dataNode);
  }
  else
  {
    std::map<std::string, MappingAttributesInfo >::iterator info = mapDataInfo.begin();
    for (; info != mapDataInfo.end(); ++info)
    {
      DataNode* dataNode = new DataNode(((*info)).first, __ntfs, mftEntryNode, mftEntryNode->isDirectory(), mftEntryNode->isUsed());
      (*info).second.mappingAttributes.unique();//pass mapping info in constructor ?
      dataNode->setMappingAttributes((*info).second);

      if (((*info).first) == name && (mftEntryInfo->node == NULL))
        mftEntryInfo->node = dataNode;
      mftEntryInfo->nodes.push_back(dataNode); 

    }
  }
  return (mftEntryInfo);
}


DValue         MFTEntryManager::saveEntries(void) const
{
  Destruct::Destruct&   destruct = Destruct::Destruct::instance();
  DObject*    dentries = destruct.generate("DMapUInt64Object");

  std::map<uint64_t, MFTEntryInfo*>::const_iterator i = this->__entries.begin();
  for (; i != this->__entries.end(); ++i) 
  {
    DObject* item = dentries->call("newItem").get<DObject*>(); 
    item->setValue("key", RealValue<DUInt64>(i->first));
    item->setValue("value", RealValue<DObject* >((i->second)->save()));
    dentries->call("setItem", RealValue<DObject*>(item));
    item->destroy();
  }

  return (RealValue<DObject*>(dentries));
}

void                    MFTEntryManager::loadEntries(DValue const& entries, Node* fsNode)
{
  std::cout << "MFTEntryManager::loadEntries(DValue entries, Node* fsNode)" << std::endl;
  uint64_t found = 0;
 
  DObject* dentries = entries.get<DObject* >();
  DObject* iterator = dentries->call("iterator").get<DObject* >();

  std::cout << "Load entries : size " << dentries->call("size").get<DUInt64>() << " " << dentries->instanceOf()->name() << std::endl;
  for (; iterator->call("isDone").get<DInt8>() != true; iterator->call("nextItem"))
  {
    DObject* item = iterator->call("currentItem").get<DObject*>();
    DValue key = item->getValue("key");
    DObject* dmftEntryInfo = item->getValue("value").get<DObject*>();
    DUInt64 entryNodeOffset = dmftEntryInfo->getValue("entryNode").get<DUInt64>();
    MFTEntryNode* mftEntryNode = NULL;

    try 
    {
      mftEntryNode = new MFTEntryNode(this->__ntfs, this->masterDataNode(), entryNodeOffset, std::string("MFTEntry"), NULL);
      DataNode* dataNode = DataNode::load(this->__ntfs, mftEntryNode, dmftEntryInfo->getValue("node")); 

      MFTEntryInfo* mftEntryInfo = new MFTEntryInfo(mftEntryNode);
      mftEntryInfo->node = dataNode;
      mftEntryInfo->nodes.push_back(dataNode);

      found++;
      this->__entries[key.get<DUInt64>()] = mftEntryInfo; 
    }
    catch (DException const& exception)
    {
      std::cout << "Error creating MFTEntryNode " << this->masterDataNode() << " " << entryNodeOffset << std::endl;
      std::cout << "Error " << exception.error() << std::endl;
    }
    catch (std::bad_cast error)
    {
      std::cout << "Error creating MFTEntryNode " << this->masterDataNode() << " " << entryNodeOffset << std::endl;
      std::cout << "Error " << error.what() << std::endl;
    }
    catch (...)
    {
      std::cout << "Error creating MFTEntryNode " << this->masterDataNode() << " " << entryNodeOffset << std::endl;
      std::cout << "Error ..." << std::endl; 
    }
    dmftEntryInfo->destroy();
    item->destroy();
  }
  iterator->destroy();
  dentries->destroy();
  std::cout << "loop end found : " << found << std::endl;
  std::cout << "MFTEntryManager::loadEntries return " << std::endl;
}

/**
 *   Link orphans entries (DataNode with a NULL parent) //in fatct link all entry  if we don't use index
 */
void    MFTEntryManager::linkOrphanEntries(void)
{
  this->__ntfs->setStateInfo("Linking orphans");
  for (uint64_t id = 0; id < this->__numberOfEntry; ++id)
  {
    MFTEntryInfo* entryInfo = this->__entries[id];
    std::list<DataNode*>::const_iterator dataNode = entryInfo->nodes.begin();
    for (; dataNode != entryInfo->nodes.end(); ++dataNode)
    {
      if (((*dataNode) == NULL) || ((*dataNode)->parent()))
        continue;
      MFTAttribute* attribute = (*dataNode)->mftEntryNode()->findMFTAttribute($FILE_NAME); //must check for all ADS too
      if (attribute)
      {
        FileName* fileName = dynamic_cast<FileName*>((attribute)->content());
        if (fileName == NULL)
          throw std::string("MFTEntryManager attribute content can't cast to $FILE_NAME"); 

        uint64_t parentId = fileName->parentMFTEntryId();
        DataNode* parent = this->node(parentId);
        if (parent)
        {
          if (fileName->parentSequence() != parent->mftEntryNode()->sequence()) 
            this->__ntfs->orphansNode()->addChild(*dataNode);
          else 
            parent->addChild(*dataNode);
        }
        delete fileName;
      }
      else
        this->__ntfs->orphansNode()->addChild(*dataNode);
   
      delete (attribute);
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
        static_cast<DObject*>(this->__unallocatedOffset)->call("push", RealValue<DUInt64>(offset));
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

  DObject* vector = this->__unallocatedOffset;
  Node*  fsNode = this->__ntfs->fsNode();

  DUInt64 count = vector->call("size").get<DUInt64>();
  for (DUInt64 index = 0; index < count; index++)
  {
    try
    {
      DUInt64 offset = vector->call("get", RealValue<DUInt64>(index)).get<DUInt64>();
      MFTEntryInfo* entryInfo = this->createFromOffset(offset, fsNode, -1);
      std::list<DataNode* >::const_iterator dataNode = entryInfo->nodes.begin(); //nodes ou node ??
      for ( ; dataNode != entryInfo->nodes.end(); ++dataNode)
      {
        if ((*dataNode))
          unallocated->addChild((*dataNode)); 
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
 *  Search for all DataNode with reparse point
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
    DataNode* dataNode = entry->second->node;
    if (dataNode)
      this->mapLink(dataNode);
  }
}

/**
 *  Create a VLink to reparse point if path is found and return VLink
 *  else return NULL
 */
Node*  MFTEntryManager::mapLink(DataNode* node) const
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

DataNode*        MFTEntryManager::masterDataNode(void) const
{
  return (this->__masterDataNode);
}

