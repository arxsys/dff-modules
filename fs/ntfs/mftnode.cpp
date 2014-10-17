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

#include <vector>

#include "ntfs.hpp"
#include "bootsector.hpp"
#include "mftnode.hpp"
#include "mftentrynode.hpp"
#include "attributes/mftattributecontenttype.hpp"

MFTNode::MFTNode(const std::string name, NTFS* ntfs, MFTEntryNode* mftEntryNode, bool isDirectory, bool isUsed) : Node(name, 0, NULL, ntfs), __mftEntryNode(mftEntryNode), __isCompressed(false)
{
  if (isDirectory)
    this->setDir();
  else
    this->setFile();
 
  if (!isUsed)
    this->setDeleted();
}

MFTNode::~MFTNode(void)
{
  if (this->__mftEntryNode != NULL)
  {
    //delete this->__mftEntryNode; //used by ads 
    this->__mftEntryNode = NULL;
  }
}

MFTEntryNode* MFTNode::mftEntryNode(MFTEntryNode* mftEntryNode)
{
  return (this->__mftEntryNode);
}

void            MFTNode::setName(const std::string name)
{
  this->__name = name;
}

void            MFTNode::setMappingAttributes(MappingAttributesInfo const&  mappingAttributesInfo)
{
  this->mappingAttributesOffset = mappingAttributesInfo.mappingAttributes;
  this->__isCompressed = mappingAttributesInfo.compressed;
  this->setSize(mappingAttributesInfo.size);
}

bool            MFTNode::isCompressed(void) const
{
  return (this->__isCompressed);
}

void		MFTNode::fileMapping(FileMapping* fm)
{
  if (this->size() == 0)
    return;

  std::list<MappingAttributes >::iterator attributeOffset = this->mappingAttributesOffset.begin();
  for (; attributeOffset != this->mappingAttributesOffset.end(); ++attributeOffset)
  {
    MappingAttributes ma = *attributeOffset;
    MFTAttribute* data = ma.entryNode->__MFTAttribute(ma.offset);
    MFTAttributeContent* content = data->content();
    content->fileMapping(fm);
    delete data;
    delete content;   
  } 
}

/**
 *  read compressed data at offset
 *  return readed data size
 */
int32_t         MFTNode::readCompressed(void* buff, unsigned int size, uint64_t* offset)
{
  uint32_t readed = 0;
  uint32_t compressionBlockSize = 0;
  uint64_t clusterSize = this->__mftEntryNode->ntfs()->bootSectorNode()->clusterSize();
  uint32_t attributeCount = 0;

  std::list<MappingAttributes >::iterator attributeOffset = this->mappingAttributesOffset.begin();
  for (; (readed < size) && (attributeOffset != this->mappingAttributesOffset.end()); ++attributeOffset)
  {
    MappingAttributes mappingAttributes = *attributeOffset;
    MFTAttribute* dataAttribute = mappingAttributes.entryNode->__MFTAttribute(mappingAttributes.offset);
    MFTAttributeContent* content = dataAttribute->content();
    Data* data = dynamic_cast<Data*>(content);  
    if (!data)
     return (0);

    if (!compressionBlockSize)
      compressionBlockSize = dataAttribute->compressionBlockSize();
    uint64_t start = dataAttribute->VNCStart() * clusterSize;
    uint64_t end = dataAttribute->VNCEnd() * clusterSize;
    if ((start <= *offset) && (*offset < end))
    {
      int32_t read = 0;
      try 
      {
        read = data->uncompress((uint8_t*)buff + readed, size - readed, *offset, compressionBlockSize);
      }
      catch (std::string const & error)
      {
        //std::cout << "MFTNode::readCompressed data uncompression error : " << error << std::endl;
      }
      if (read  <= 0)
        break;
      if (*offset + read > this->size())
      {
        readed += this->size() - *offset;
        *offset = this->size();
        break;
      }
      *offset += read;
      readed += read;
    }
    attributeCount++;
    delete data;
    delete dataAttribute;
  }
  return (readed);
}

Attributes	MFTNode::_attributes(void)
{
  if (this->__mftEntryNode != NULL)
    return (this->__mftEntryNode->_attributes());
  Attributes attr;
  return (attr);
}

Destruct::DObject*      MFTNode::save(void) //const
{
  Destruct::Destruct& destruct = Destruct::Destruct::instance();
  Destruct::DObject* mftNode = destruct.generate("MFTNode");

  mftNode->setValue("name", Destruct::RealValue<Destruct::DUnicodeString>(this->name())); 
  if (__mftEntryNode)
    mftNode->setValue("mftEntryNode", Destruct::RealValue<DUInt64>(__mftEntryNode->offset()));
  mftNode->setValue("isDirectory", Destruct::RealValue<DUInt8>(this->isDir()));
  if (this->isDeleted()) 
    mftNode->setValue("isUsed", Destruct::RealValue<DUInt8>(0));
  else
    mftNode->setValue("isUsed", Destruct::RealValue<DUInt8>(1));
  ///XX XXX XXX size size size !!! ou c ds les mapping attribute enfin faut savoir ! 

  mftNode->setValue("size", Destruct::RealValue<DUInt64>(this->__size));
  mftNode->setValue("isCompressed", Destruct::RealValue<DUInt8>(this->__isCompressed));

  Destruct::DObject* dmappingAttributes = destruct.generate("DVectorObject");
  std::list<MappingAttributes>::const_iterator ma = this->mappingAttributesOffset.begin();
  for (; ma != this->mappingAttributesOffset.end(); ++ma)
  {
     Destruct::DObject* dma = ma->save(); 
     dmappingAttributes->call("push", Destruct::RealValue<Destruct::DObject*>(dma));
  }

  mftNode->setValue("mappingAttributes", Destruct::RealValue<Destruct::DObject*>(dmappingAttributes));
// a desesrialize des MFTEntryNode // check doublon et pas cree 2 fois ? 
// donc du coup les truc qui sont ds MFTEntryInfo->nodes(push) ca sert a ququchose ou c les meme ????
// ou c juste pour les passer en param ??
//std::cout << this->

  return (mftNode);
}


MFTNode*        MFTNode::load(NTFS* ntfs, MFTEntryNode* entryNode, Destruct::DValue const& args)
{
  Destruct::DObject* dnode = args.get<Destruct::DObject*>();
  if (dnode != Destruct::DNone)
  {
    Destruct::DUnicodeString dnodeName = dnode->getValue("name").get<Destruct::DUnicodeString>();
    DUInt8 dnodeIsDirectory =  dnode->getValue("isDirectory").get<DUInt8>();
    DUInt8 dnodeIsUsed =  dnode->getValue("isUsed").get<DUInt8>(); 
    DUInt8 dnodeIsCompressed =  dnode->getValue("isCompressed").get<DUInt8>(); 
    DUInt64 dnodeSize =  dnode->getValue("size").get<DUInt64>(); 
    //mapping attributes
    MappingAttributesInfo mappingAttributesInfo;
    mappingAttributesInfo.size = dnodeSize;
    mappingAttributesInfo.compressed = dnodeIsCompressed;
   
    Destruct::DObject* dmappingAttributes = dnode->getValue("mappingAttributes").get<Destruct::DObject*>();
    DUInt64 size = dmappingAttributes->call("size").get<DUInt64>();

    for (DUInt64 index = 0; index < size; ++index)
    {
      Destruct::DValue mappingAttributes = dmappingAttributes->call("get", Destruct::RealValue<DUInt64>(index));
      mappingAttributesInfo.mappingAttributes.push_back(MappingAttributes::load(ntfs, entryNode->mftNode(), mappingAttributes));
    }    

    dmappingAttributes->destroy();
    dnode->destroy();

    try 
    {
      //std::cout << "creating node " << dnodeName << std::endl;
      MFTNode* mftNode = new MFTNode(dnodeName, ntfs, entryNode, dnodeIsDirectory, dnodeIsUsed);
      mftNode->setMappingAttributes(mappingAttributesInfo);     
 
      return (mftNode);
    }
    catch (...)
    {  
      std::cout << "Catch MFTNode " << std::endl;
      return (NULL);
    }
  }

  return (NULL);
}

/**
 *  MappingAttributes
 */

bool    MappingAttributes::operator==(MappingAttributes const& other)
{
     if ((other.offset == offset) && (other.entryNode == entryNode))
       return (true);
     return (false);
}

Destruct::DObject* MappingAttributes::save(void) const
{
  Destruct::DObject* ma = Destruct::Destruct::instance().generate("MappingAttributes");

  ma->setValue("offset", Destruct::RealValue<DUInt16>(offset));
  ma->setValue("mftEntryNode", Destruct::RealValue<DUInt64>(entryNode->offset()));

  return (ma);
}


MappingAttributes     MappingAttributes::load(NTFS* ntfs, Node* mftNode,  Destruct::DValue const& args)
{
  Destruct::DObject* dma = args.get<Destruct::DObject* >();

  uint16_t offset = dma->getValue("offset").get<DUInt16>();
  uint64_t mftEntryNodeOffset = dma->getValue("mftEntryNode").get<DUInt64>();
  
  MFTEntryNode* mftEntryNode  = new MFTEntryNode(ntfs, mftNode, mftEntryNodeOffset, "MFTEntry", NULL); //MANAGER 

  dma->destroy();
  return (MappingAttributes(offset, mftEntryNode));;
}
