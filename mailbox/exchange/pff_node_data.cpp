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

PffNodeData::PffNodeData(std::string name, Node* parent, fso* fsobj) : Node(name, 0, parent, fsobj)
{
  this->setFile();
}


PffNodeData::PffNodeData(std::string name, Node* parent, fso* fsobj, libpff_item_t *item_data, libpff_file_t** file, bool clone) : Node(name, 0, parent, fsobj)
  
{
  int result;

  this->pff_item = NULL;
  libpff_error_t* pff_error = NULL;
  //if (clone == false) //XXX ???
  //{
    result = libpff_item_get_identifier(item_data, &(this->identifier), &pff_error);
    if (result == 0 || result == -1)
    {
      check_error(pff_error) 
      std::cout << "PffNodeData() can't get item by id, clonning" << std::endl;
      this->pff_item = new libpff_item_t*;
      *(this->pff_item) = NULL;
      if (libpff_item_clone(this->pff_item, item_data, &pff_error) != 1)
        check_error(pff_error) 
    }
    //}
    //else
    //{
    //this->pff_item = new libpff_item_t*;
    //*(this->pff_item) = NULL;
    //libpff_item_clone(this->pff_item, item_data, error);
    //}
  this->setFile();
  this->pff_file = file;
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


