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

#include "key.hpp"
#include "value.hpp"
//#include "regf.hpp"

#include "streamvfile.hpp"
#include "registry.hpp"

using namespace Destruct;

/**
 * RegistryValues
 */
RegistryValues::RegistryValues(DStruct* dstruct, DValue const& args) : DCppObject<RegistryValues>(dstruct, args)
{
  this->init();
  this->parent = args.get<DObject* >();
  this->list = Destruct::Destruct::instance().generate("DVectorObject");
  ((DObject*)list)->addRef();
}

RegistryValues::~RegistryValues(void)
{
}

DValue    RegistryValues::deserializeRaw(DValue const& arg)
{
  StreamVFile* stream = static_cast<StreamVFile*>(arg.get<DObject*>());
  DStruct* valueStruct = Destruct::Destruct::instance().find("RegistryValue"); 

  DUInt32 valueCount = ((DObject*)this->parent)->getValue("valueCount").get<DUInt32>();
  DUInt32 valueListOffset = ((DObject*)this->parent)->getValue("valueListOffset").get<DUInt32>();
  if (valueCount == 0 || valueListOffset == 0xffffffff)
  {
    stream->destroy();   
    return (RealValue<DUInt8>(1));
  }

  stream->seek(valueListOffset + 0x1000); 
  size.unserialize(*stream);

  Destruct::DSerialize* serializer = Destruct::DSerializers::to("Raw");
  for (uint32_t index = 0; index < valueCount ; ++index)
  {
    RealValue<DUInt32> subvalueOffset;
        
    subvalueOffset.unserialize(*stream);
    DObject* subvalue = valueStruct->newObject();
    int64_t currentOffset = stream->tell();
    stream->seek(subvalueOffset + 0x1000);
    serializer->deserialize(*stream, subvalue);
    stream->seek(currentOffset);

    
    ((DObject*)this->list)->call("push", RealValue<DObject*>(subvalue)); 
  }

  stream->destroy();
  delete serializer;

  return (RealValue<DUInt8>(1));
}

/**
 * RegistryValues
 */
RegistryValue::RegistryValue(DStruct* dstruct, DValue const& args) : DCppObject<RegistryValue>(dstruct, args)
{
  this->init();
  this->name = new NameLength(Destruct::Destruct::instance().find("NameLength"), RealValue<DObject*>(this));
  ((DObject*)this->name)->setValue("attributeKeyName", RealValue<DUnicodeString>("nameLength"));
  ((DObject*)this->name)->addRef();
  
 this->data = new RegistryValueData(Destruct::Destruct::instance().find("RegistryValueData"), RealValue<DObject*>(this));
 ((DObject*)this->data)->addRef();
}

RegistryValue::~RegistryValue(void)
{
}

DValue    RegistryValue::deserializeRaw(DValue const& arg)
{
  //Destruct::Destruct& destruct = Destruct::Destruct::instance();

  //destruct.generate(this->dataTypeName[this->dataType]);

  return (RealValue<DUInt8>(1));
}

/**
 * RegistryValueData
 */
RegistryValueData::RegistryValueData(DStruct* dstruct, DValue const& args) : DCppObject<RegistryValueData>(dstruct, args)
{

  this->init();
}

RegistryValueData::~RegistryValueData(void)
{
}


DValue    RegistryValueData::deserializeRaw(DValue const& arg)
{
  return (RealValue<DUInt8>(1));
}
