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

#include "ntfsopt.hpp"

NTFSOpt::NTFSOpt(Attributes args)
{
  this->__fsNode = NULL;
  this->__validateBootSector = true;

  if (args.find("file") != args.end())
    this->__fsNode = args["file"]->value<Node* >();
  else
    throw envError("NTFS module need a file argument.");
  if (args.find("no-bootsector-check") != args.end())
    this->__validateBootSector = false;
}

NTFSOpt::~NTFSOpt(void)
{
}

Node*   NTFSOpt::fsNode(void)
{
  return (this->__fsNode);
}

bool    NTFSOpt::validateBootSector(void)
{
  return (this->__validateBootSector);
}
