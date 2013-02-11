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

PffNodeEmailTransportHeaders::PffNodeEmailTransportHeaders(std::string name, Node* parent, fso* fsobj, libpff_item_t *mail, libpff_file_t** file, bool clone) : PffNodeEMail(name, parent, fsobj, mail, file, clone)
{
  size_t 	headers_size  = 0; 
  libpff_error_t* pff_error   = NULL;

  if (libpff_message_get_utf8_transport_headers_size(mail, &headers_size, &pff_error) == 1)
  {
    if (headers_size > 0)
       this->setSize(headers_size); 
  }
  else
    check_error(pff_error)
}

uint8_t*	PffNodeEmailTransportHeaders::dataBuffer(void)
{
  uint8_t*		entry_string = NULL;
  libpff_item_t*	item         = NULL;
  libpff_error_t*       pff_error    = NULL;

  if (this->size() <= 0)
    return (NULL);

  if (this->pff_item == NULL)
  {
    if (libpff_file_get_item_by_identifier(*(this->pff_file), this->identifier, &item, &pff_error) != 1)
    {
      check_error(pff_error)
      return (NULL);
    }
  }
  else
    item = *(this->pff_item);	
  entry_string =  new uint8_t [this->size()];
  if (libpff_message_get_utf8_transport_headers(item, entry_string, this->size(), &pff_error ) != 1 )
  {
    check_error(pff_error)
    if (this->pff_item == NULL)
      if (libpff_item_free(&item, &pff_error) != 1)
        check_error(pff_error)
    delete entry_string;
    return (NULL);
  }
 
  if (this->pff_item == NULL)
    if (libpff_item_free(&item, &pff_error) != 1)
      check_error(pff_error)
  return (entry_string);
}

