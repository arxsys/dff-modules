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
#include "regf.hpp"

#include "streamvfile.hpp"

using namespace Destruct;

/**
 *  RegistryKey
 */
RegistryKey::RegistryKey(DStruct* dstruct, DValue const& args) : DCppObject<RegistryKey>(dstruct, args)
{
  this->init();
  
  this->timestamp = new RegfTime64(Destruct::Destruct::instance().find("RegfTime64"), RealValue<DObject*>(DNone));
  this->keyName = new NameLength(Destruct::Destruct::instance().find("NameLength"), RealValue<DObject*>(this));
  ((DObject*)this->keyName)->setValue("attributeKeyName", RealValue<DUnicodeString>("keyNameLength"));

  this->subkeys = new Subkeys(Destruct::Destruct::instance().find("Subkeys"), RealValue<DObject*>(this));
  this->values = new RegistryValues(Destruct::Destruct::instance().find("RegistryValues"), RealValue<DObject*>(this));
  ((DObject*)this->timestamp)->addRef();
  ((DObject*)this->keyName)->addRef();
  ((DObject*)this->subkeys)->addRef();
}

RegistryKey::~RegistryKey(void)
{
}

/**
 * NameLength 
 */
NameLength::NameLength(DStruct* dstruct, DValue const& args) : DCppObject<NameLength>(dstruct, args)
{
  this->init();
  this->parent = args.get<DObject* >();
}

NameLength::~NameLength(void)
{
}

DValue    NameLength::deserializeRaw(DValue const& arg)
{
  DStream* stream = static_cast<DStream*>(arg.get<DObject*>());

  DUInt16 size = ((DObject*)this->parent)->getValue(this->attributeKeyName).get<DUInt16>();

  char keyNameBuff[size];
  stream->read(keyNameBuff, size);
  stream->destroy();

  this->keyName = std::string(keyNameBuff, size);

  return (RealValue<DUInt8>(1));
}


/**
 * Subkeys
 */
Subkeys::Subkeys(DStruct* dstruct, DValue const& args) : DCppObject<Subkeys>(dstruct, args)
{
  this->init();
  this->parent = args.get<DObject* >();
  this->list = Destruct::Destruct::instance().generate("DVectorObject");
  ((DObject*)list)->addRef();
}

Subkeys::~Subkeys(void)
{
}

DValue    Subkeys::deserializeRaw(DValue const& arg)
{
  StreamVFile* stream = static_cast<StreamVFile*>(arg.get<DObject*>());
  DStruct* keyStruct = Destruct::Destruct::instance().find("RegistryKey"); 

  //XXX IF SUBKEY COUNT IN PARENT ?
  DUInt32 parentSubkeyCount = ((DObject*)this->parent)->getValue("subkeyCount").get<DUInt32>();
  DUInt32 subkeyListOffset = ((DObject*)this->parent)->getValue("subkeyListOffset").get<DUInt32>();
  if (parentSubkeyCount == 0 || subkeyListOffset == 0xffffffff)
  {
    stream->destroy();    
    return (RealValue<DUInt8>(1));
  }

  stream->seek(subkeyListOffset + 0x1000); 
  
  size.unserialize(*stream);
  signature.unserialize(*stream);
  subkeyCount.unserialize(*stream);
 
  Destruct::DSerialize* serializer = Destruct::DSerializers::to("Raw");

  if (signature == 0x686c || signature == 0x666c || signature == 0x6972 || signature == 0x696c)
  {
    for (uint32_t index = 0; index < subkeyCount; ++index)
    {
      RealValue<DUInt32> subkeyOffset, subkeyChecksum;
      subkeyOffset.unserialize(*stream);
      if (signature == 0x686c || signature == 0x666c) //LH || LI 
      {
        subkeyChecksum.unserialize(*stream);
      }
   
      DObject* subkey = keyStruct->newObject();
      int64_t currentOffset = stream->tell();
      stream->seek(subkeyOffset + 0x1000);
      serializer->deserialize(*stream, subkey);
      stream->seek(currentOffset);

      ((DObject*)this->list)->call("push", RealValue<DObject*>(subkey)); 
    }

  }
  else 
     std::cout << "Key bad signature" << std::hex << signature << std::endl;

  stream->destroy();
  delete serializer;

  return (RealValue<DUInt8>(1));
}

