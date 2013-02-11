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

#include <sstream>
#include "pff.hpp"

void pff::export_sub_items(libpff_item_t *item, Node* parent)
{
  libpff_error_t* pff_error           = NULL;
  libpff_item_t*  sub_item            = NULL;
  int 		  number_of_sub_items = 0;
  int 		  sub_item_iterator   = 0;

  if (libpff_item_get_number_of_sub_items(item, &number_of_sub_items, &(pff_error)) != 1)
  {
    std::string error_name = "error on " + parent->name();
    this->res[error_name] = new Variant(std::string("Unable to retrieve number of items."));
    check_error(pff_error)
    return ;
  }
  for (sub_item_iterator = 0; sub_item_iterator < number_of_sub_items; sub_item_iterator++)
  {
    if (libpff_item_get_sub_item(item, sub_item_iterator, &sub_item, &(pff_error)) != 1)
    {
      error_on_item("Unable to retrieve subitem", sub_item_iterator, parent)
      check_error(pff_error)
      continue ;
    }
    this->export_item(sub_item, sub_item_iterator, parent);
    if (libpff_item_free(&sub_item, &(pff_error)) != 1)
    {
      error_on_item("Unable to free subitem", sub_item_iterator, parent)
      check_error(pff_error)
      continue ;
    }
  } 
}

int pff::export_item(libpff_item_t* item, int item_index, Node* parent, bool clone)
{
  libpff_error_t* pff_error           = NULL;
  uint8_t 	item_type		= 0;
  int 		result			= 0;

  if (libpff_item_get_type(item, &item_type, &(pff_error)) != 1)
  {
    check_error(pff_error)
    return (0);
  }
  if (item_type == LIBPFF_ITEM_TYPE_ACTIVITY)
  {
    result = this->export_message_default(item, item_index, parent, clone, std::string("Activity"));
  }
  else if (item_type == LIBPFF_ITEM_TYPE_APPOINTMENT)
  {
    result = this->export_appointment(item, item_index, parent, clone);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_CONTACT)
  {
    result = this->export_contact(item, item_index, parent, clone);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_DOCUMENT)
  {
    result = this->export_message_default(item, item_index, parent, clone, std::string("Document"));
  }
  else if (item_type == LIBPFF_ITEM_TYPE_CONFLICT_MESSAGE || item_type == LIBPFF_ITEM_TYPE_EMAIL || item_type == LIBPFF_ITEM_TYPE_EMAIL_SMIME)
  {
    result = this->export_email(item, item_index, parent, clone);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_FOLDER)
  {
    result = this->export_folder(item, item_index, parent, clone);
  }
  else if (item_type == LIBPFF_ITEM_TYPE_MEETING)
  {
    result = this->export_meeting(item, item_index, parent, clone); 
  }
  else if (item_type == LIBPFF_ITEM_TYPE_NOTE)
  {
    result = this->export_note(item, item_index, parent, clone);	
  }
  else if (item_type == LIBPFF_ITEM_TYPE_RSS_FEED)
  {
    result = this->export_message_default(item, item_index, parent, clone, std::string("RSS"));
  }
  else if (item_type == LIBPFF_ITEM_TYPE_TASK)
  {
    result = this->export_task(item, item_index, parent, clone);
  }
  else
  {
    error_on_item("Exporting unknown type for item", item_index, parent)
    result = 1;
  }
 return (result);
}

int pff::export_message_default(libpff_item_t* item, int item_index, Node* parent, bool clone, std::string item_type_name)
{
  std::ostringstream folderName;

  folderName << std::string(item_type_name) << item_index + 1;
  PffNodeFolder* nodeFolder = new PffNodeFolder(folderName.str(), parent, this);

  new PffNodeEmailMessageText(std::string(item_type_name), nodeFolder, this, item, &(this->pff_file), clone);

  return (1);
}

int pff::export_note(libpff_item_t* note, int note_index, Node* parent, bool clone)
{
  libpff_error_t* pff_error           = NULL;
  std::ostringstream 	folderName;
  size_t 		subject_string_size = 0;
  int 			result;

  result = libpff_message_get_utf8_subject_size(note, &subject_string_size, &(pff_error));
  if (result != 0 && result != -1 && subject_string_size > 0)
  {
    char*	subject = (char*)malloc(sizeof(char *) * subject_string_size);
    if (libpff_message_get_utf8_subject(note, (uint8_t*)subject, subject_string_size, &(pff_error)) != 1)
      check_error(pff_error)
    folderName << std::string(subject);
    free(subject);
  }    
  else
  {
    check_error(pff_error)
    folderName << "Note" << note_index + 1;
  }
  PffNodeFolder* nodeFolder = new PffNodeFolder(folderName.str(), parent, this);

  new PffNodeNote("Note", nodeFolder, this, note, &(this->pff_file), clone);

  return (1);
}

int pff::export_meeting(libpff_item_t* note, int note_index, Node* parent, bool clone)
{
  libpff_error_t* pff_error           = NULL;
  std::ostringstream 	folderName;
  size_t 		subject_string_size = 0;
  int 			result;

  result = libpff_message_get_utf8_subject_size(note, &subject_string_size, &(pff_error));
  if (result != 0 && result != -1 && subject_string_size > 0)
  {
    char*	subject = (char*)malloc(sizeof(char *) * subject_string_size);
    if (libpff_message_get_utf8_subject(note, (uint8_t*)subject, subject_string_size, &(pff_error)) != 1)
      check_error(pff_error)
    folderName << std::string(subject);
    free(subject);
  }    
  else
  {
    check_error(pff_error)
    folderName << "Meeting" << note_index + 1;
  } 
  PffNodeFolder* nodeFolder = new PffNodeFolder(folderName.str(), parent, this);

  new PffNodeMeeting("Meeting", nodeFolder, this, note, &(this->pff_file), clone);

  return (1);
}

int pff::export_task(libpff_item_t* task, int task_index, Node* parent, bool clone)
{
  libpff_error_t* pff_error           = NULL;
  std::ostringstream 	taskName;
  size_t 		subject_string_size = 0;
  int 			result;

  result = libpff_message_get_utf8_subject_size(task, &subject_string_size, &(pff_error));
  if (result != 0 && result != -1 && subject_string_size > 0)
  {
    char*	subject = (char*)malloc(sizeof(char *) * subject_string_size);
    if (libpff_message_get_utf8_subject(task, (uint8_t*)subject, subject_string_size, &(pff_error)) != 1)
      check_error(pff_error)
    taskName << std::string(subject);
    free(subject);
  }    
  else
  {
    check_error(pff_error)
    taskName << std::string("Task") << task_index + 1;
  }
  PffNodeFolder* nodeFolder = new PffNodeFolder(taskName.str(), parent, this);

  new PffNodeTask(std::string("Task"), nodeFolder, this, task, &(this->pff_file), clone);

  this->export_attachments(task, nodeFolder, clone);

  return (1);
}


int pff::export_contact(libpff_item_t* contact, int contact_index, Node* parent, bool clone)
{
  libpff_error_t* pff_error           = NULL;
  std::ostringstream 	contactName;
  size_t 		subject_string_size = 0;
  int 			result;

  result = libpff_message_get_utf8_subject_size(contact, &subject_string_size, &(pff_error));
  if (result != 0 && result != -1 && subject_string_size > 0)
  {
    char*	subject = (char*)malloc(sizeof(char *) * subject_string_size);
    if (libpff_message_get_utf8_subject(contact, (uint8_t*)subject, subject_string_size, &(pff_error)) != -1)
      check_error(pff_error)
    contactName << std::string(subject);
    free(subject);
  }    
  else
  { 
    check_error(pff_error)
    contactName << std::string("Contact") << contact_index + 1;
  }
  PffNodeFolder* nodeFolder = new PffNodeFolder(contactName.str(), parent, this);

  new PffNodeContact(std::string("Contact"), nodeFolder, this, contact, &(this->pff_file), clone);

  this->export_attachments(contact, nodeFolder, clone);

  return (1);
}

int pff::export_appointment(libpff_item_t* appointment, int appointment_index, Node* parent, bool clone)
{
  libpff_error_t* pff_error           = NULL;
  std::ostringstream 	messageName; 
  size_t 		subject_string_size = 0;
  int 			result;

  result = libpff_message_get_utf8_subject_size(appointment, &subject_string_size, &(pff_error));
  if (result != 0 && result != -1 && subject_string_size > 0)
  {
    char*	subject = (char*)malloc(sizeof(char *) * subject_string_size);
    if (libpff_message_get_utf8_subject(appointment, (uint8_t*)subject, subject_string_size, &(pff_error)) != -1)
      check_error(pff_error)
    messageName << std::string(subject);
    free(subject);
  }    
  else
  {
    check_error(pff_error)
    messageName << std::string("Appointment")  << appointment_index + 1;
  } 
  PffNodeFolder* nodeFolder = new PffNodeFolder(messageName.str(), parent, this);

  new PffNodeAppointment(std::string("Appointment"), nodeFolder, this, appointment, &(this->pff_file), clone);

  this->export_attachments(appointment, nodeFolder, clone);

  return (1);
}

int pff::export_folder(libpff_item_t* folder, int folder_index, Node* parent, bool clone)
{
  libpff_error_t* pff_error           = NULL;
  PffNodeFolder* 	subFolder	 = NULL;
  uint8_t*	 	folder_name	 = NULL;
  size_t 		folder_name_size = 0;
  int 			result		 = 0;

  result = libpff_folder_get_utf8_name_size(folder, &folder_name_size, &(pff_error));
  if (result == 0 || result == -1 || folder_name_size == 0)
  {
    std::ostringstream folderName;

    folderName << std::string("Folder") << folder_index + 1;
    subFolder = new PffNodeFolder(folderName.str(), parent, this);
  }
  else
  {
    folder_name = (uint8_t *) new uint8_t[folder_name_size];
    result = libpff_folder_get_utf8_name(folder, folder_name, folder_name_size, NULL);
    subFolder = new PffNodeFolder(std::string((char *)folder_name), parent, this);
  }

  if (export_sub_folders(folder, subFolder) != 1)
  {
    check_error(pff_error)
    error_on_item("Unable to export subfolders", folder_index, subFolder)
    return (0);
  }
  if (export_sub_messages(folder, subFolder) != 1)
  {
    check_error(pff_error)
    error_on_item("Unable to export submessages", folder_index, subFolder)
    return (0);
  }

  return (1);
}

int pff::export_email(libpff_item_t* email, int email_index, Node *parent, bool clone)
{
  libpff_error_t* pff_error           = NULL;
  size_t 	email_html_body_size = 0;
  size_t 	email_rtf_body_size = 0;
  size_t 	email_text_body_size = 0;
  size_t	transport_headers_size = 0;
  size_t 	subject_string_size = 0;
  int 		result;
  int 		has_html_body = 0;
  int 		has_rtf_body = 0;
  int 		has_text_body = 0;

  std::ostringstream messageName; 

  result = libpff_message_get_utf8_subject_size(email, &subject_string_size, &(pff_error));
  if (result != 0 && result != -1 && subject_string_size > 0)
  {
    char*	subject = (char*)malloc(sizeof(char *) * subject_string_size);
    if (libpff_message_get_utf8_subject(email, (uint8_t*)subject, subject_string_size, &(pff_error)) != -1)
      check_error(pff_error)
    messageName << std::string(subject);
    free(subject);
  }    
  else
  {
    check_error(pff_error)
    messageName << std::string("Message")  << email_index + 1;
  }
  has_html_body = libpff_message_get_html_body_size(email, &email_html_body_size, &(pff_error));
  has_rtf_body = libpff_message_get_rtf_body_size(email, &email_rtf_body_size, &(pff_error));
  has_text_body = libpff_message_get_plain_text_body_size(email, &email_text_body_size, &(pff_error)); 
  
  PffNodeFolder* nodeFolder = new PffNodeFolder(messageName.str(), parent, this);

  if (libpff_message_get_utf8_transport_headers_size(email, &transport_headers_size, &(pff_error)) == 1)
  {
    if (transport_headers_size > 0)
      new PffNodeEmailTransportHeaders("Transport Headers", nodeFolder, this, email, &(this->pff_file), clone);
  }
  else
    check_error(pff_error)
    
  if (has_text_body == 1)
  {
    new PffNodeEmailMessageText("Message", nodeFolder, this, email, &(this->pff_file), clone);
  }
  else
    check_error(pff_error)
  if (has_html_body == 1)
  {
    new PffNodeEmailMessageHTML("Message HTML", nodeFolder, this, email, &(this->pff_file), clone);
  }
  else
    check_error(pff_error)
  if (has_rtf_body == 1)
  {
    new PffNodeEmailMessageRTF("Message RTF", nodeFolder, this, email, &(this->pff_file), clone);
  }
  else
    check_error(pff_error)

  this->export_attachments(email, nodeFolder, clone);

  return (1);
}

int pff::export_attachments(libpff_item_t* item, Node* parent, bool clone)
{
  int		result 				= 0;
  int 		attachment_type         	= 0;
  int 		attachment_iterator     	= 0;
  int 		number_of_attachments   	= 0;
  size_t 	attachment_filename_size	= 0;
  size64_t 	attachment_data_size            = 0;
  uint8_t*	attachment_filename     	= NULL;
  libpff_error_t* pff_error           = NULL;

  if (libpff_message_get_number_of_attachments(item, &number_of_attachments, &(pff_error) ) != 1 )
  {
    check_error(pff_error)
    return (-1);
  }
  if (number_of_attachments <= 0)
  {
    check_error(pff_error)
    return (-1);
  }
  for (attachment_iterator = 0; attachment_iterator < number_of_attachments; attachment_iterator++)
  {
    libpff_item_t *attachment			= NULL;
     if (libpff_message_get_attachment(item, attachment_iterator, &attachment, &(pff_error)) != 1)
     {
       check_error(pff_error)
       continue ;
     }
     if (libpff_attachment_get_type(attachment, &attachment_type, &(pff_error)) != 1)
     {
       check_error(pff_error)
       if (libpff_item_free(&attachment, &(pff_error)) != 1)
         check_error(pff_error)
       continue;    
     }
     if ((attachment_type != LIBPFF_ATTACHMENT_TYPE_DATA)
         && (attachment_type != LIBPFF_ATTACHMENT_TYPE_ITEM)
         && (attachment_type != LIBPFF_ATTACHMENT_TYPE_REFERENCE))
     {
	if (libpff_item_free(&attachment, &(pff_error)) != 1)
          check_error(pff_error)
        continue;
     }
     if ((attachment_type == LIBPFF_ATTACHMENT_TYPE_REFERENCE))
     {
       if (libpff_item_free(&attachment, &(pff_error)) != 1)
          check_error(pff_error)
       continue;
     }
     if (attachment_type == LIBPFF_ATTACHMENT_TYPE_DATA)
       if (libpff_attachment_get_utf8_long_filename_size(attachment, &attachment_filename_size,&(pff_error)) != 1)
          check_error(pff_error)

     attachment_filename = new uint8_t[attachment_filename_size];
     if (attachment_filename == NULL)
     {
       if (libpff_item_free(&attachment, &(pff_error)) == 1)
          check_error(pff_error)
       delete attachment_filename;
       continue;
     }	
     std::ostringstream attachmentName;
     if (attachment_type == LIBPFF_ATTACHMENT_TYPE_DATA)
     {
       if ( libpff_attachment_get_utf8_long_filename(attachment, attachment_filename, attachment_filename_size, NULL ) != 1 )
  	 attachmentName << std::string("Attachment") << attachment_iterator + 1;
       else 
         attachmentName << std::string((char*)attachment_filename);
  
     }
     else if (attachment_type == LIBPFF_ATTACHMENT_TYPE_ITEM)
  	 attachmentName << std::string("Attachment") << attachment_iterator + 1;

     if (attachment_type == LIBPFF_ATTACHMENT_TYPE_DATA)
     {
	 result = libpff_attachment_get_data_size(attachment, &attachment_data_size, &(pff_error));
         if (result == -1)
	 {
           check_error(pff_error)
	   libpff_item_free(&attachment, &(pff_error));
	   delete attachment_filename;
	   continue;
	 }
         if ((result != 0) && (attachment_data_size > 0 ))
	 {
	   new PffNodeAttachment(attachmentName.str(), parent, this, item, attachment_data_size, &(this->pff_file), attachment_iterator, clone);
	   delete attachment_filename;
	   libpff_item_free(&attachment, &(pff_error));
	 }
     }    
     else if(attachment_type == LIBPFF_ATTACHMENT_TYPE_ITEM)
     {
	libpff_item_t**	attached_item = new libpff_item_t*;
	*attached_item = NULL;
	if (libpff_attachment_get_item(attachment, attached_item, &(pff_error)) == 1)
	{
          uint8_t	item_type;
	  PffNodeFolder* folder = new PffNodeFolder(attachmentName.str(), parent, this);		
          this->export_item(*attached_item, 0, folder, true);
          if (libpff_item_get_type(*attached_item, &item_type, &(pff_error)) == 1)
            if (item_type != LIBPFF_ITEM_TYPE_APPOINTMENT)
	      libpff_item_free(attached_item, &(pff_error)); //didn't free because can't clone appointment
	}
	else
	{
          check_error(pff_error)
	  delete attached_item;
	}
	if (libpff_item_free(&attachment, &(pff_error)) != 1)
          check_error(pff_error)
	delete attachment_filename;
     }
  }
  return (1);
}

int pff::export_sub_folders(libpff_item_t* folder, PffNodeFolder* nodeFolder)
{
  libpff_item_t* sub_folder = NULL; 
  int 		number_of_sub_folders = 0;
  int 		sub_folder_iterator   = 0;
  libpff_error_t* pff_error           = NULL;

  if (libpff_folder_get_number_of_sub_folders(folder, &number_of_sub_folders, &(pff_error)) != 1)
  {
    check_error(pff_error)
    std::string error_name = "error on " + nodeFolder->name();
    this->res[error_name] = new Variant(std::string("Unable to retrieve number of subfolders"));
    return (0);
  }
  for (sub_folder_iterator = 0; sub_folder_iterator < number_of_sub_folders; sub_folder_iterator++)
  {
     if (libpff_folder_get_sub_folder(folder, sub_folder_iterator, &sub_folder, &(pff_error)) != 1)
     {
       check_error(pff_error)
       error_on_item("Unable to retrieve subfolders", sub_folder_iterator, nodeFolder)
       continue ;
     }
     if (export_folder(sub_folder, sub_folder_iterator, nodeFolder, false) != 1)
     {
       error_on_item("Unable to export subfolder", sub_folder_iterator, nodeFolder)
       continue ;
     }
     if (libpff_item_free(&sub_folder, &(pff_error)) != 1)
     {
       check_error(pff_error)
       error_on_item("Unable to free subfolder", sub_folder_iterator, nodeFolder)
       continue ;
     }
  }
  return (1);
}

int pff::export_sub_messages(libpff_item_t* folder, PffNodeFolder* nodeFolder)
{
  libpff_item_t *sub_message = NULL; 
  int number_of_sub_messages = 0;
  int sub_message_iterator   = 0;
  libpff_error_t* pff_error           = NULL;

  if (libpff_folder_get_number_of_sub_messages(folder, &number_of_sub_messages, &(pff_error)) != 1)
  {
    std::string error_name = "error on " + nodeFolder->name();
    this->res[error_name] = new Variant(std::string("Unable to retrieve number of submessages"));
    return (0);
  }
  for (sub_message_iterator = 0; sub_message_iterator < number_of_sub_messages; sub_message_iterator++)
  {
     if (libpff_folder_get_sub_message(folder, sub_message_iterator, &sub_message, &(pff_error)) != 1)
     {
       check_error(pff_error)
       error_on_item("Unable to retrieve submessage", sub_message_iterator, nodeFolder) 
       continue ;	
     }
     if (export_item(sub_message, sub_message_iterator, nodeFolder) != 1)
     {
       error_on_item("Unable to export submessage", sub_message_iterator, nodeFolder) 
       continue ;
     }
     if (libpff_item_free(&sub_message, &(pff_error)) != 1)
     {
       check_error(pff_error)
       error_on_item("Unable to free submessage", sub_message_iterator, nodeFolder) 
       continue ;
     }
  }

  return (1);
}
