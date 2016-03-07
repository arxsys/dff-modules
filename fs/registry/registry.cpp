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

Registry::Registry() : mfso("Registry"), __rootNode(NULL)
{
  
}

Registry::~Registry()
{
}

Destruct::DObject*      Registry::open(void)
{
  RealValue<DObject*> regf = DStructs::instance().generate("Regf");

  DStruct* streamVFileS = new DStruct(NULL, "StreamVFile", DCppObject<StreamVFile>::newObject, StreamVFile::ownAttributeBegin(), StreamVFile::ownAttributeEnd());

  RealValue<DObject*> streamVFile = new StreamVFile(streamVFileS, this->__rootNode->open());
  
  RealValue<DObject*> deserializer = DStructs::instance().generate("DeserializeRaw", streamVFile);

  ((DObject*)streamVFile)->destroy();
  ((DObject*)deserializer)->call("DObject", regf);

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

//void    Registry::createValue(DObject* value)
//{
//
//}

void    Registry::createNodeTree(DObject* regf)
{
  Node* regfNode  = new RegfNode(regf, this->__rootNode, this);
  DObject* key = regf->getValue("key");
  this->createKeyNode(key, regfNode);
}

void    Registry::start(Attributes args)
{
  if (args.find("file") != args.end())
    this->__rootNode = args["file"]->value<Node* >();
  else
    throw envError("Registry module need a file argument.");


  this->setStateInfo("Parsing registry");

  //must no do it everytime module is loaded
  DObject* imp = DStructs::instance().generate("Import"); 
  imp->call("file", RealValue<DUnicodeString>("dff/api/destruct/examples/modules/libregistry.so"));
  DObject* regf = this->open();

  this->setStateInfo("Creating registry nodes");
  this->createNodeTree(regf);
  //regf->destroy();
//registerTree() 

  this->setStateInfo("Finished successfully");
  this->res["Result"] = Variant_p(new DFF::Variant(std::string("Registry module applyied successfully.")));
}

void    Registry::setStateInfo(const std::string& info)
{
  this->stateinfo = info;
}
