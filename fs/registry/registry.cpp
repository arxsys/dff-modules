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

#include "variant.hpp"
#include "node.hpp"
#include "exceptions.hpp"
#include "dstructs.hpp"
#include "dstruct.hpp"

#include "registry.hpp"
#include "streamvfile.hpp"
#include "registrynode.hpp"

using namespace Destruct;
using namespace DFF;

Registry::Registry() : mfso("Registry"), __rootNode(NULL), __major(1), __minor(5)
{
  
}

Registry::~Registry()
{
}

uint32_t                Registry::versionMajor(void) const
{
  return (this->__major);
}

uint32_t                Registry::versionMinor(void) const
{
  return (this->__minor);
}

Node*                   Registry::rootNode(void) const
{
  return (this->__rootNode);
}

Destruct::DObject*      Registry::open(void)
{
  RealValue<DObject*> regf = DStructs::instance().generate("Regf");

  DStruct* streamVFileS = new DStruct(NULL, "StreamVFile", DCppObject<StreamVFile>::newObject, StreamVFile::ownAttributeBegin(), StreamVFile::ownAttributeEnd());

  RealValue<DObject*> streamVFile = new StreamVFile(streamVFileS, this->__rootNode->open());
  
  RealValue<DObject*> deserializer = DStructs::instance().generate("DeserializeRaw", streamVFile);

  ((DObject*)streamVFile)->destroy();
  ((DObject*)deserializer)->call("DObject", regf);
  this->__major = ((DObject*)regf)->getValue("major");
  this->__minor = ((DObject*)regf)->getValue("minor");

  return (regf);
}

void    Registry::createKeyNode(DObject* key, Node* parent)
{
  Node* keyNode = new KeyNode(key, parent, this);

  DObject* values = key->getValue("values");
  DObject* valuesList = values->getValue("list");
  DUInt64  valuesCount = valuesList->call("size");
  for (DUInt64 index = 0; index != valuesCount; ++index)
  {
    DObject* values = valuesList->call("get", RealValue<DUInt64>(index));
    new ValueNode(values, keyNode, this);
    values->destroy();
  }

  DObject* subkeys = key->getValue("subkeys");
  DObject* subkeysList = subkeys->getValue("list");
  DUInt64  subkeysCount = subkeysList->call("size");
  for (DUInt64 index = 0; index != subkeysCount; ++index)
  {  
    DObject* subKey = subkeysList->call("get", RealValue<DUInt64>(index));
    this->createKeyNode(subKey, keyNode);
    subKey->destroy();
  }
}

void    Registry::createNodeTree(DObject* regf)
{
  Node* regfNode  = new RegfNode(regf, this);
  DObject* key = regf->getValue("key");
  this->createKeyNode(key, regfNode);
  this->registerTree(this->__rootNode, regfNode);
}

void    Registry::start(Attributes args)
{
  if (args.find("file") != args.end())
    this->__rootNode = args["file"]->value<Node* >();
  else
    throw envError("Registry module need a file argument.");

  this->setStateInfo("Parsing registry");

  //must no do it everytime module is loaded
  try
  {
    DObject* regf = this->open();

    this->setStateInfo("Creating registry nodes");
    this->createNodeTree(regf);
    regf->destroy();

    this->setStateInfo("Finished successfully");
    this->res["Result"] = Variant_p(new DFF::Variant(std::string("Registry module applyied successfully.")));
 }
 catch (Destruct::DException const& exception)
 {
   this->res["Result"] = Variant_p(new DFF::Variant(std::string(exception.error())));
   throw DFF::envError(exception.error());
 }
}

void    Registry::setStateInfo(const std::string& info)
{
  this->stateinfo = info;
}
