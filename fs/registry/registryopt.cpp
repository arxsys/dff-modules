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

#include "registryopt.hpp"

using namespace Destruct;

RegistryOpt::RegistryOpt(Attributes args, DStruct* dstruct) : DCppObject<RegistryOpt>(dstruct), __fsNode(NULL) 
{
  Attributes::iterator arg;
  this->init();

  if (args.find("file") != args.end())
  {
    Node* node = args["file"]->value<Node* >();
    this->__fsNode = new NodeContainer(Destruct::Destruct::instance().find("NodeContainer"), node);
  }
  else
    throw envError("Registry module need a file argument.");
}


RegistryOpt::RegistryOpt(DStruct* dstruct, DValue const& dargs) : DCppObject<RegistryOpt>(dstruct, dargs)
{
  this->init();
}

RegistryOpt::~RegistryOpt(void)
{
}

Node*           RegistryOpt::fsNode(void) const
{
  return (static_cast<NodeContainer*>(static_cast<DObject*>(this->__fsNode))->node());
}
