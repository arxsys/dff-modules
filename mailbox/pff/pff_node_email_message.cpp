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


PffNodeEmailMessageText::PffNodeEmailMessageText(std::string name, Node* parent, fso* fsobj, libpff_item_t *mail, libpff_error_t** error, libpff_file_t** file, bool clone) : PffNodeEMail(name, parent, fsobj, mail, error, file, clone)
{
  size_t 	headers_size  = 0; 
  
  if (libpff_message_get_plain_text_body_size(mail, &headers_size, this->pff_error) == 1)
  {
    if (headers_size > 0)
       this->setSize(headers_size); 
  }
}

uint8_t*	PffNodeEmailMessageText::dataBuffer(void)
{
  uint8_t*		entry_string = NULL;
  libpff_item_t*	item = NULL;
  
  if (this->size() <= 0)
    return (NULL);
 
  if (this->pff_item == NULL)
  { 
  if (libpff_file_get_item_by_identifier(*(this->pff_file), this->identifier, &item, this->pff_error) != 1)
  
     return (NULL);
  }
  else 
    item = *(this->pff_item);	
  entry_string =  new uint8_t [this->size()];
  if (libpff_message_get_plain_text_body(item, entry_string, this->size(), this->pff_error ) != 1)
  {
    if (this->pff_item == NULL)
       libpff_item_free(&item, this->pff_error);
    delete entry_string;
    return (NULL);
  }

  if (this->pff_item == NULL)
    libpff_item_free(&item, this->pff_error);
  return (entry_string);
}


PffNodeEmailMessageHTML::PffNodeEmailMessageHTML(std::string name, Node* parent, fso* fsobj, libpff_item_t *mail, libpff_error_t** error, libpff_file_t** file, bool clone) : PffNodeEMail(name, parent, fsobj, mail, error, file, clone)
{
  size_t 	headers_size  = 0; 

  if (libpff_message_get_html_body_size(mail, &headers_size, this->pff_error) == 1)
  {
    if (headers_size > 0)
       this->setSize(headers_size); 
  }
}

uint8_t*	PffNodeEmailMessageHTML::dataBuffer(void)
{
  uint8_t*		entry_string = NULL;
  libpff_item_t*	item = NULL;

  if (this->size() <= 0)
    return (NULL);

  if (this->pff_item == NULL)
  {	
    if (libpff_file_get_item_by_identifier(*(this->pff_file), this->identifier, &item, this->pff_error) != 1)
     return (NULL);
  }
  else
    item = *(this->pff_item);	
  entry_string =  new uint8_t [this->size()];
  if (libpff_message_get_html_body(item, entry_string, this->size(), this->pff_error ) != 1)
  {
    if (this->pff_item == NULL)
      libpff_item_free(&item, this->pff_error);
    delete entry_string;
    return (NULL);
  }

  if (this->pff_item == NULL)
    libpff_item_free(&item, this->pff_error);
  return (entry_string);
}

PffNodeEmailMessageRTF::PffNodeEmailMessageRTF(std::string name, Node* parent, fso* fsobj, libpff_item_t *mail, libpff_error_t** error, libpff_file_t** file, bool clone) : PffNodeEMail(name, parent, fsobj, mail, error, file, clone)
{
  size_t 	headers_size  = 0; 

  if (libpff_message_get_rtf_body_size(mail, &headers_size, this->pff_error) == 1)
  {
    if (headers_size > 0)
       this->setSize(headers_size); 
  }
}

uint8_t*	PffNodeEmailMessageRTF::dataBuffer(void)
{
  uint8_t*		entry_string = NULL;
  libpff_item_t*	item = NULL;

  if (this->size() <= 0)
    return (NULL);

  if (this->pff_item == NULL)
  {	
    if (libpff_file_get_item_by_identifier(*(this->pff_file), this->identifier, &item, this->pff_error) != 1)
     return (NULL);
  }
  else
    item = *(this->pff_item);

  entry_string =  new uint8_t [this->size()];
  if (libpff_message_get_rtf_body(item, entry_string, this->size(), this->pff_error ) != 1 )
  {
    if (this->pff_item == NULL)
      libpff_item_free(&item, this->pff_error);
    delete entry_string;
    return (NULL);
  }

  if (this->pff_item == NULL)
    libpff_item_free(&item, this->pff_error);
  return (entry_string);
}

PffNodeNote::PffNodeNote(std::string name, Node* parent, fso* fsobj, libpff_item_t* item, libpff_error_t** error, libpff_file_t** file, bool clone) : PffNodeEmailMessageText(name, parent, fsobj, item, error, file, clone)
{
}

std::string PffNodeNote::icon()
{
  return (":notes");
}

PffNodeMeeting::PffNodeMeeting(std::string name, Node* parent, fso* fsobj, libpff_item_t* item, libpff_error_t** error, libpff_file_t** file, bool clone) : PffNodeEmailMessageText(name, parent, fsobj, item, error, file, clone)
{
}

std::string PffNodeMeeting::icon()
{
  return (":meeting");
}
