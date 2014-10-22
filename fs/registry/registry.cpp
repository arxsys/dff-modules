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

#include "registry.hpp"
#include "registryopt.hpp"
#include "regf.hpp"
#include "key.hpp"
#include "value.hpp"

#include "streamvfile.hpp"

void    Registry::declare(void)
{
  Destruct::Destruct& destruct = Destruct::Destruct::instance();

  registerDCpp(StreamVFile)
  registerDCpp(RegistryOpt)
  registerDCpp(Regf)
  registerDCpp(RegfName)
  registerDCpp(RegfTime64)
  registerDCpp(RegistryKey)
  registerDCpp(NameLength)
  registerDCpp(Subkeys)
  registerDCpp(RegistryValue)
  registerDCpp(RegistryValues)
  registerDCpp(RegistryValueData)
}

Registry::Registry(Destruct::DStruct* dstruct) : mfso("Registry"), DCppObject<Registry>(dstruct), __opt(NULL), __regf(NULL), __destruct(Destruct::Destruct::instance())
{
  std::cout << "Registry(DStruct* dstruct" << std::endl;
}

Registry::Registry(Registry const& copy) : mfso("Registry"), DCppObject<Registry>(copy), __opt(NULL), __regf(NULL), __destruct(Destruct::Destruct::instance())
{
  std::cout << "Registry(Registry const&" << std::endl;
}

Registry::Registry() :  mfso("Registry"), DCppObject<Registry>(NULL), __opt(NULL), __regf(NULL), __destruct(Destruct::Destruct::instance())
{
  std::cout << "Registry() DStruct is NULL" << std::endl;
}

Registry::~Registry()
{
}

void    Registry::start(Attributes args)
{
  std::cout << "Registry::start(args)" << std::endl;
  this->__opt = new RegistryOpt(args, this->__destruct.find("RegistryOpt"));
  this->__regf = new Regf(this->__destruct.find("Regf"), Destruct::RealValue<Destruct::DObject*>(Destruct::DNone));
  VFile* vfile = this->__opt->fsNode()->open();
  StreamVFile* streamVFile = new StreamVFile(vfile, this->__destruct.find("StreamVFile"));

  this->show(this->__opt);   
  this->show(streamVFile);   
  
  Destruct::DSerialize* serializer = Destruct::DSerializers::to("Raw");
  serializer->deserialize(*streamVFile, this->__regf);

  if (this->__regf->validate().get<DUInt8>())
    std::cout << "Registry file is valid" << std::endl;
  else
    std::cout << "Registry file is invalid" << std::endl;

  std::cout << "time stamp " << this->__regf->time().get<Destruct::DUnicodeString>() << std::endl
            << "version " << this->__regf->version().get<Destruct::DUnicodeString>() << std::endl;

  RegistryKey* key = new RegistryKey(Destruct::Destruct::instance().find("RegistryKey"), RealValue<DObject*>(DNone));
  DInt64 x = 0x1000 + this->__regf->keyrecord;
  streamVFile->seek(x);
  serializer->deserialize(*streamVFile, key);
  this->__regf->key = key;
  delete serializer;
 
  std::cout << key->instanceOf()->name() << " " << key->refCount() << std::endl; 

  this->toFile("registry.bin", this->__regf, "Binary");
  this->toFile("registry.text", this->__regf, "Text");
  //this->show(this->__regf);  

 //this->setStateInfo("Finished successfully");
 //this->res["Result"] = Variant_p(new Variant(std::string("Registry parsed successfully.")));
}

void            Registry::toFile(std::string filePath, Destruct::DObject* object, std::string type)
{
  Destruct::Destruct& destruct = Destruct::Destruct::instance();

  DMutableObject* arg = static_cast<DMutableObject*>(destruct.generate("DMutable"));
  arg->setValueAttribute(DType::DUnicodeStringType, "filePath", RealValue<DUnicodeString>(filePath)); 
  arg->setValueAttribute(DType::DInt8Type, "input", RealValue<DInt8>(DStream::Output));
  DStream* dstream = static_cast<Destruct::DStream*>(destruct.generate("DStream", Destruct::RealValue<Destruct::DObject*>(arg)));
  arg->destroy();

  DSerialize* serializer = DSerializers::to(type);

  serializer->serialize(*dstream, object);
  delete serializer;
  dstream->destroy(); 
}

void            Registry::show(Destruct::DObject* object)
{
  Destruct::DStream* cout = static_cast<Destruct::DStream*>(Destruct::Destruct::instance().generate("DStreamCout"));
  Destruct::DSerialize* text = Destruct::DSerializers::to("Text");

  text->serialize(*cout, object);

  delete text;
  cout->destroy();
  
}

RegistryOpt*	Registry::opt(void) const
{
  return (this->__opt);
}

Regf*           Registry::regf(void) const
{
  return (this->__regf);
}

/** Loading and saving method **/
bool                    Registry::load(Destruct::DValue value)
{
  return (false);
}

Destruct::DValue   Registry::save(void) const
{
  return (Destruct::RealValue<Destruct::DObject*>(Destruct::DNone));
}


