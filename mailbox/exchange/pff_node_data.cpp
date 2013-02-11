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

#include "pff.hpp"

PffNodeData::PffNodeData(std::string name, Node* parent, fso* fsobj, libpff_error_t** error) : Node(name, 0, parent, fsobj)
  
{
  this->setFile();
  this->pff_error = error;
}


PffNodeData::PffNodeData(std::string name, Node* parent, fso* fsobj, libpff_item_t *item_data, libpff_error_t** error, libpff_file_t** file, bool clone) : Node(name, 0, parent, fsobj)
  
{
  int result;

  this->pff_item = NULL;
  if (clone == 0)
  {
    result = libpff_item_get_identifier(item_data, &(this->identifier), error);
    if (result == 0 || result == -1)
    {
      this->pff_item = new libpff_item_t*;
      *(this->pff_item) = NULL;
      libpff_item_clone(this->pff_item, item_data, error);
    }
  }
  else
  {
    this->pff_item = new libpff_item_t*;
    *(this->pff_item) = NULL;
    libpff_item_clone(this->pff_item, item_data, error);
  }
  this->setFile();
  this->pff_file = file;
  this->pff_error = error;
}

fdinfo* PffNodeData::vopen(void)
{
  return (NULL);
}

int32_t PffNodeData::vread(fdinfo* fi, void *buff, unsigned int size)
{
  return (0);
}

int32_t PffNodeData::vclose(fdinfo* fi)
{
 return (-1);
}

uint64_t PffNodeData::vseek(fdinfo* fd, uint64_t offset, int whence)
{
  return (0);
}


