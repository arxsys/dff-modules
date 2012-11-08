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

#ifndef __PFF_NODE_HH__
#define __PFF_NODE_HH__

#include "pff.hpp"

class PffNodeFolder : public Node
{
public:
  EXPORT PffNodeFolder(std::string name, Node* parent, fso* fsobj);
  EXPORT ~PffNodeFolder();
  std::string		icon(void);
};

class PffNodeData : public Node
{
public:
  EXPORT 		        PffNodeData(std::string name, Node* parent, fso* fsobj, libpff_error_t**);
  EXPORT 		        PffNodeData(std::string name, Node* parent, fso* fsobj, libpff_item_t *dataItem, libpff_error_t**, libpff_file_t**, bool clone);
  virtual fdinfo*       	vopen();
  virtual int32_t 	        vread(fdinfo* fi, void *buff, unsigned int size);
  virtual int32_t 	        vclose(fdinfo* fi);
  virtual uint64_t      	vseek(fdinfo* fi, uint64_t offset, int whence);
  libpff_error_t**	        pff_error;
  libpff_file_t**		pff_file;
  uint32_t			identifier;
  libpff_item_t**       	pff_item;
};

class PffNodeEMail : public PffNodeData
{
private:
  int			        attributesMessageHeader(Attributes* attr, libpff_item_t* item);
  int 			        attributesMessageConversationIndex(Attributes* attr, libpff_item_t* item);
  int			        attributesRecipients(Attributes* attr, libpff_item_t* item);
  int			        attributesTransportHeaders(Attributes* attr, libpff_item_t* item);
  void 			        splitTextToAttributes(std::string text, Attributes* attr);
public:
  Attributes			allAttributes(libpff_item_t* item);	
  EXPORT 		        PffNodeEMail(std::string name, Node* parent, fso* fsobj, libpff_error_t** );
  EXPORT 		        PffNodeEMail(std::string name, Node* parent, fso* fsobj, libpff_item_t *mail, libpff_error_t**, libpff_file_t**, bool clone);
  EXPORT virtual Attributes     _attributes(void);
  fdinfo*       		vopen(void);
  int32_t 	       	 	vread(fdinfo* fi, void *buff, unsigned int size);
  int32_t 	        	vclose(fdinfo* fi);
  uint64_t		      	vseek(fdinfo* fi, uint64_t offset, int whence);
  virtual uint8_t *	        dataBuffer(void);
  std::string			icon(void);
};

class PffNodeEmailTransportHeaders : public PffNodeEMail
{
public:
  EXPORT		        PffNodeEmailTransportHeaders(std::string, Node*, fso*, libpff_item_t*, libpff_error_t**, libpff_file_t**, bool clone);
  EXPORT uint8_t *	        dataBuffer(void);
};

class PffNodeEmailMessageText : public PffNodeEMail
{
public:
  EXPORT			PffNodeEmailMessageText(std::string , Node*, fso*, libpff_item_t*, libpff_error_t**, libpff_file_t**, bool clone);
  EXPORT uint8_t*		dataBuffer(void);
};

class PffNodeEmailMessageHTML : public PffNodeEMail
{
public:
  EXPORT			PffNodeEmailMessageHTML(std::string , Node*, fso*, libpff_item_t*, libpff_error_t**, libpff_file_t**, bool clone);
  EXPORT uint8_t*		dataBuffer(void);
};

class PffNodeEmailMessageRTF : public PffNodeEMail
{
public:
  EXPORT			PffNodeEmailMessageRTF(std::string , Node*, fso*, libpff_item_t*, libpff_error_t**, libpff_file_t**, bool clone);
  EXPORT uint8_t*		dataBuffer(void);
};

class PffNodeAttachment : public PffNodeEMail 
{
  int				attachment_iterator;
public:
  EXPORT 		        PffNodeAttachment(std::string name, Node* parent, fso* fsobj, libpff_item_t *mail, libpff_error_t**, size64_t, libpff_file_t**, int attachment_iterator, bool clone);
  EXPORT uint8_t*		dataBuffer(void);
  EXPORT std::string		icon(void);
};

class PffNodeAppointment : public PffNodeEMail
{
public:
  EXPORT	PffNodeAppointment(std::string name, Node *parent, fso* fsobj, libpff_item_t* appointment, libpff_error_t**, libpff_file_t**, bool clone);
  EXPORT virtual Attributes     _attributes(void);
  EXPORT void  	                attributesAppointment(Attributes* attr, libpff_item_t*);
  EXPORT std::string		icon(void);
};


class PffNodeContact : public PffNodeEmailMessageText
{
public:
  EXPORT PffNodeContact(std::string name, Node* parent, fso* fsobj, libpff_item_t* contact, libpff_error_t**, libpff_file_t**, bool clone);
  EXPORT virtual Attributes 	_attributes(void);
  EXPORT void			attributesContact(Attributes* attr, libpff_item_t*);
  EXPORT std::string		icon(void);
};

class PffNodeTask : public PffNodeEmailMessageText
{
public:
  EXPORT PffNodeTask(std::string name, Node* parent, fso* fsobj, libpff_item_t* task, libpff_error_t**, libpff_file_t** file, bool clone);
  EXPORT virtual Attributes   	_attributes(void);
  EXPORT void		      	attributesTask(Attributes* attr, libpff_item_t*); 
  EXPORT std::string		icon(void);
};

class PffNodeMeeting : public PffNodeEmailMessageText
{
public:
  EXPORT PffNodeMeeting(std::string name, Node* parent, fso* fsobj, libpff_item_t* task, libpff_error_t**, libpff_file_t** file, bool clone);
  EXPORT  std::string		icon(void); 
};

class PffNodeNote : public PffNodeEmailMessageText
{
public:
  EXPORT PffNodeNote(std::string name, Node* parent, fso* fsobj, libpff_item_t* task, libpff_error_t**, libpff_file_t** file, bool clone);
  EXPORT std::string	icon(void);
};

class PffNodeUnallocatedBlocks : public Node
{
private:
 Node*			root;
 int			block_type;
 libpff_error_t**	pff_error;
 libpff_file_t**	pff_file;
 uint32_t		identifier;
public:
 EXPORT			PffNodeUnallocatedBlocks(std::string name, Node* parent, mfso* fsobj, Node* root,int block_type, libpff_error_t**, libpff_file_t**);
 virtual void		fileMapping(FileMapping* fm);
};

#endif
