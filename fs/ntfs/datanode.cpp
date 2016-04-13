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
#include "datanode.hpp"
#include "mftentrynode.hpp"
#include "attributes/mftattributecontenttype.hpp"

using namespace Destruct;

DataNode::DataNode(NTFS* ntfs, const std::string name, MFTNode* mftEntryNode) : Node(name, 0, NULL, ntfs), __mftEntryNode(mftEntryNode), __isCompressed(false)
{
  if (mftEntryNode->isDirectory())
    this->setDir();
  else
    this->setFile();
 
  if (!(mftEntryNode->isUsed()))
    this->setDeleted();
}

DataNode::~DataNode(void)
{
  if (this->__mftEntryNode != NULL)
  {
    //delete this->__mftEntryNode; //used by ads 
    this->__mftEntryNode = NULL;
  }
}

MFTNode* DataNode::mftEntryNode(MFTNode* mftEntryNode)
{
  return (this->__mftEntryNode);
}

void            DataNode::setName(const std::string name)
{
  this->__name = name;
}

void            DataNode::setMappingAttributes(MappingAttributesInfo const& mappingAttributesInfo)
{
  this->mappingAttributesOffset = mappingAttributesInfo.mappingAttributes;
  this->__isCompressed = mappingAttributesInfo.compressed;
  this->setSize(mappingAttributesInfo.size);
}

bool            DataNode::isCompressed(void) const
{
  return (this->__isCompressed);
}

void		DataNode::fileMapping(FileMapping* fm)
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
int32_t         DataNode::readCompressed(void* buff, unsigned int size, uint64_t* offset)
{
  uint32_t readed(0);
  uint32_t compressionBlockSize(0);
  uint32_t attributeCount(0);
  uint64_t clusterSize(this->__mftEntryNode->ntfs()->bootSectorNode()->clusterSize());

  std::list<MappingAttributes >::iterator attributeOffset = this->mappingAttributesOffset.begin();
  for (; (readed < size) && (attributeOffset != this->mappingAttributesOffset.end()); ++attributeOffset)
  {
    MappingAttributes mappingAttributes(*attributeOffset);
    MFTAttribute* dataAttribute(mappingAttributes.entryNode->__MFTAttribute(mappingAttributes.offset));
    MFTAttributeContent* content(dataAttribute->content());
    Data* data(dynamic_cast<Data*>(content));
    if (!data)
    {
      delete content;
      delete dataAttribute;
      return (0);
    }

    if (!compressionBlockSize)
      compressionBlockSize = dataAttribute->compressionBlockSize();
    uint64_t start(dataAttribute->VNCStart() * clusterSize);
    uint64_t end(dataAttribute->VNCEnd() * clusterSize);
    if ((start <= *offset) && (*offset < end))
    {
      int32_t read = 0;
      try 
      {
        read = data->uncompress((uint8_t*)buff + readed, size - readed, *offset, compressionBlockSize);
      }
      catch (std::string const & error)
      {
        //std::cout << "DataNode::readCompressed data uncompression error : " << error << std::endl;
      }
      if (read  <= 0)
      {
        delete data;
        delete dataAttribute;
        break;
      }
      if (*offset + read > this->size())
      {
        readed += this->size() - *offset;
        *offset = this->size();
        delete data;
        delete dataAttribute;
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

Attributes	DataNode::_attributes(void)
{
  if (this->__mftEntryNode != NULL)
    return (this->__mftEntryNode->_attributes());
  Attributes attr;
  return (attr);
}

DValue      DataNode::save(void) const
{
  Destruct::DStructs& destruct = Destruct::DStructs::instance();
  DObject* dataNode = destruct.generate("DataNode");

  dataNode->setValue("name", RealValue<DUnicodeString>(this->name())); 
  if (this->__mftEntryNode)
  {
    DObject* mftEntryNode = this->__mftEntryNode->save();
    dataNode->setValue("mftEntryNode", RealValue<DObject*>(mftEntryNode));
    mftEntryNode->destroy();
  }
  dataNode->setValue("size", RealValue<DUInt64>(this->__size));
  dataNode->setValue("isCompressed", RealValue<DUInt8>(this->__isCompressed));

  DObject* dmappingAttributes = destruct.generate("DVectorObject");
  std::list<MappingAttributes>::const_iterator ma = this->mappingAttributesOffset.begin();
  for (; ma != this->mappingAttributesOffset.end(); ++ma)
  {
    DObject* mappingSave  = ma->save();
    dmappingAttributes->call("push", RealValue<DObject*>(mappingSave));
    mappingSave->destroy();
  }
  dataNode->setValue("mappingAttributes", RealValue<DObject*>(dmappingAttributes));
  dmappingAttributes->destroy();

  // a desesrialize des MFTNode // check doublon et pas cree 2 fois ? 
  // donc du coup les truc qui sont ds MFTEntryInfo->nodes(push) ca sert a ququchose ou c les meme ????
  // ou c juste pour les passer en param ??

  return (RealValue<DObject*>(dataNode));
}

DataNode*        DataNode::load(NTFS* ntfs, DValue const& args)
{
  //ici map <offset, mftentrynode> //comme ca on gardes les pointeur pour pas les recree deux fois ? 
  // bien reflechir si ca arrive pourquoi $MFT marche pas et d autre truc ds le genre ...
  DObject* dnode = args.get<DObject*>();
  if (dnode != DNone)
  {
    MFTNode* mftEntryNode(NULL);
    DUnicodeString name(dnode->getValue("name").get<DUnicodeString>());
    DObject* mftEntryNodeObject = dnode->getValue("mftEntryNode").get<DObject*>();
    if (mftEntryNodeObject->instanceOf()->name() == "MFTNode")
      mftEntryNode = MFTNode::load(ntfs, RealValue<DObject*>(mftEntryNodeObject));
    else //MFTNode
      mftEntryNode = MFTEntryNode::load(ntfs, RealValue<DObject*>(mftEntryNodeObject));
    DataNode* dataNode(new DataNode(ntfs, name, mftEntryNode));
    //mftEntryNodeObject->destroy();

    MappingAttributesInfo mappingAttributesInfo;
    mappingAttributesInfo.size = dnode->getValue("size").get<DUInt64>();
    mappingAttributesInfo.compressed = dnode->getValue("isCompressed").get<DUInt8>();
   
    DObject* dmappingAttributes(dnode->getValue("mappingAttributes").get<DObject*>());
    DUInt64 size(dmappingAttributes->call("size").get<DUInt64>());

    for (DUInt64 index = 0; index < size; ++index)
    {
      DValue ma(dmappingAttributes->call("get", RealValue<DUInt64>(index)));
      mappingAttributesInfo.mappingAttributes.push_back(MappingAttributes::load(ntfs, ma));
    }   
    //dmappingAttributes->destroy();
    dataNode->setMappingAttributes(mappingAttributesInfo);     
    //dnode->destroy();
    return (dataNode);
  }

  //dnode->destroy();
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

DValue  MappingAttributes::save(void) const
{
  DObject* ma =  Destruct::DStructs::instance().generate("MappingAttributes");

  ma->setValue("offset", RealValue<DUInt16>(offset));
  DObject* mftEntryNode = entryNode->save();
  ma->setValue("mftEntryNode", RealValue<DObject*>(mftEntryNode));
  mftEntryNode->destroy();

  return (RealValue<DObject*>(ma));
}

MappingAttributes     MappingAttributes::load(NTFS* ntfs, DValue const& args)
{
  DObject* dma(args.get<DObject* >());

  uint16_t offset(dma->getValue("offset").get<DUInt16>());
  DObject* mftEntryNodeObject = dma->getValue("mftEntryNode");
  MFTNode* mftEntryNode(NULL);

  if (mftEntryNodeObject->instanceOf()->name() == "MFTNode")
    mftEntryNode = MFTNode::load(ntfs, RealValue<DObject*>(mftEntryNodeObject));
  else
    mftEntryNode = MFTEntryNode::load(ntfs, RealValue<DObject*>(mftEntryNodeObject));

  //mftEntryNodeObject->destroy(); 
  //dma->destroy();
  return (MappingAttributes(offset, mftEntryNode));;
}
