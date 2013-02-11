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

//When an attachment is attached to an attachment we need to clone the last object,
//for 'normal' attachment we must get it from identifier and iterator first and then get the object.
PffNodeAttachment::PffNodeAttachment(std::string name, Node* parent, fso* fsobj, libpff_item_t *item, size64_t size, libpff_file_t**  file, int attachment_iterator, bool clone) : PffNodeEMail(name, parent, fsobj)
{
  int result;
  libpff_error_t* pff_error = NULL;
  this->pff_file = file;  
  this->pff_item = NULL;
  this->attachment_iterator = attachment_iterator;
  this->setSize(size); 

  //this->identifier = item->identifier;// ??
  libpff_item_get_identifier(item, &(this->identifier), &pff_error);


  //if (clone == false)
  //{
  //result = libpff_item_get_identifier(item, &(this->identifier), &pff_error); //?
    result = libpff_file_get_item_by_identifier(*(this->pff_file), this->identifier, &item, &pff_error);
    if (result != 0 && result != -1)
    {
      std::cout << "PffNodeAttachment() can't get item by id " << std::endl;
      return ;
    }
    //}
  this->pff_item = new libpff_item_t*;
  *(this->pff_item) = NULL;
  result = libpff_message_get_attachment(item, attachment_iterator, (this->pff_item), &pff_error);
  if (result != 1)
    check_error(pff_error) 
}


std::string	PffNodeAttachment::icon(void)
{
  return (":attach");
}

uint8_t*	PffNodeAttachment::dataBuffer(void)
{
  uint8_t*		buff = NULL;
  libpff_item_t*	item = NULL;
  libpff_item_t* 	attachment = NULL;
  libpff_error_t*       pff_error = NULL;
  int			result = 0;

  if (this->size() <= 0)
    return (NULL);

  if (this->pff_item == NULL)
  {
     result = libpff_file_get_item_by_identifier(*(this->pff_file), this->identifier, &item, &pff_error);
    if (result == 0 || result == -1)
    {
       check_error(pff_error) 
       return (NULL);
    }
    result = libpff_message_get_attachment(item, attachment_iterator, &attachment, &pff_error);
    if (result == 0 || result == -1)
    {
      check_error(pff_error) 
      return (NULL);
    }
  }
  else
  {
    attachment = *(this->pff_item);
  }
  buff =  new uint8_t[this->size()];
  
  ssize_t read_count                         = 0;

  if (libpff_attachment_data_seek_offset(attachment, 0, SEEK_SET, &pff_error) != 0)
  {
    check_error(pff_error) 
    if (this->pff_item == NULL)
    {
      if (libpff_item_free(&attachment, &pff_error) != 1)
        check_error(pff_error) 
      if (libpff_item_free(&item, &pff_error) != 1)
        check_error(pff_error) 
    }
    return (NULL);
  }
  read_count = libpff_attachment_data_read_buffer(attachment, (uint8_t*)buff , this->size(), &pff_error);
  if (read_count != (ssize_t)this->size())
    check_error(pff_error) 

  if (this->pff_item == NULL)
  {
    if (libpff_item_free(&attachment, &pff_error) != 1)
        check_error(pff_error) 
    if (libpff_item_free(&item, &pff_error) != 1)
        check_error(pff_error) 
  }
  return buff;
}
