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

pff::pff() : mfso("pff")
{
  
}

pff::~pff()
{
  libpff_file_close(this->pff_file, &(this->pff_error));
  libpff_file_free(&(this->pff_file),  &(this->pff_error));
}

void pff::start(std::map<std::string, Variant_p > args)
{
  std::string 	path;
  
  if (args.find("file") != args.end())
    this->parent = args["file"]->value<Node* >();
  else
    throw envError("pff need a file argument.");
  try 
  {
    this->initialize(this->parent);
    this->info();
    if (args.find("unallocated") == args.end())
    {
      this->stateinfo = std::string("Searching unallocated data"); 
      this->create_unallocated();
    }
    if (args.find("recoverable") == args.end())
    {
      this->stateinfo = std::string("Searching recoverable items");
      this->create_recovered();
    }
    if (args.find("orphan") == args.end())
    {
      this->stateinfo = std::string("Searching orphan items");
      this->create_orphan();
    }
    if (args.find("default") == args.end())
    {
      this->stateinfo = std::string("Creating mailbox items");
      this->create_item();
    }
  }
  catch (vfsError e)
  {
    this->res["error"] = Variant_p(new Variant(e.error));
    this->stateinfo = std::string(e.error);
    return ;
  }
  this->stateinfo = std::string("Mailbox parsed successfully");
  res["Result"] = Variant_p(new Variant(std::string("Mailbox parsed successfully.")));
}

void    pff::create_recovered(void)
{
  int 				number_of_recovered_items 	= 0; 
  int 				recovered_item_iterator  	= 0;  
  int				number_of_found_recovered_items = 0;
  libpff_item_t*		pff_recovered_item		= NULL;
                                            
  if (libpff_file_recover_items(this->pff_file, 0, &(this->pff_error)) != 1)
    return ;
  if (libpff_file_get_number_of_recovered_items(this->pff_file, &number_of_recovered_items, &(this->pff_error)) != 1)
    return ;

  if (number_of_recovered_items > 0)
  {
     Node* recoveredNode = new Node(std::string("recovered"), 0, NULL, this);
     for (recovered_item_iterator = 0; recovered_item_iterator < number_of_recovered_items; recovered_item_iterator++)
     {
       if (libpff_file_get_recovered_item(this->pff_file, recovered_item_iterator, &pff_recovered_item, &(this->pff_error)) == 1)
       {
         if (pff_recovered_item != NULL)
         {
	   this->export_item(pff_recovered_item, recovered_item_iterator, recoveredNode, 1);
           libpff_item_free(&pff_recovered_item, &(this->pff_error));  
           number_of_found_recovered_items++; 
         }
       }
     }
     this->res["Number of recovered items"] = Variant_p(new Variant(number_of_found_recovered_items));
     this->registerTree(this->parent, recoveredNode); 
  }
}

void	pff::create_orphan()
{
  int			orphan_item_iterator 	= 0;
  int			number_of_orphan_items 	= 0; 
  int			number_of_found_orphan_items = 0;
  libpff_item_t*	pff_orphan_item 	= NULL;

  if (libpff_file_get_number_of_orphan_items(this->pff_file, &(number_of_orphan_items), &(this->pff_error)) != 1)
    return ;
  if (number_of_orphan_items > 0)
  {
     Node* orphansNode = new Node(std::string("orphans"), 0, NULL, this);
     for (orphan_item_iterator = 0; orphan_item_iterator < number_of_orphan_items; orphan_item_iterator++)
     {
        if (libpff_file_get_orphan_item(this->pff_file, orphan_item_iterator, &pff_orphan_item, &(this->pff_error)) == 1)
        {
          if (pff_orphan_item != NULL)
          {
            this->export_item(pff_orphan_item, orphan_item_iterator, orphansNode, 1);
	    libpff_item_free(&pff_orphan_item, &(this->pff_error));
	    number_of_found_orphan_items++;
          }
        } 
     }
     this->registerTree(this->parent, orphansNode); 
     this->res["Number of orphan items"] = Variant_p(new Variant(number_of_found_orphan_items));
  } 
}

void	pff::create_unallocated(void)
{
   PffNodeUnallocatedBlocks*  unallocatedPage = new PffNodeUnallocatedBlocks(std::string("unallocated page blocks"), NULL, this, this->parent, LIBPFF_UNALLOCATED_BLOCK_TYPE_PAGE, &(this->pff_error), &(this->pff_file));
   this->registerTree(this->parent, unallocatedPage);

   PffNodeUnallocatedBlocks*  unallocatedData = new PffNodeUnallocatedBlocks(std::string("unallocated data blocks"), NULL, this, this->parent, LIBPFF_UNALLOCATED_BLOCK_TYPE_DATA, &(this->pff_error), &(this->pff_file));
   this->registerTree(this->parent, unallocatedData);
}


void pff::create_item()
{
   libpff_item_t *pff_root_item = NULL;
   int number_of_sub_items      = 0;

   if (libpff_file_get_root_folder(this->pff_file, &pff_root_item, &(this->pff_error)) != 1)
      throw vfsError(std::string("Unable to retrieve root item"));
   if (libpff_item_get_number_of_sub_items(pff_root_item, &number_of_sub_items, &(this->pff_error)) != 1)
      throw vfsError(std::string("Unable to retrive number of sub items."));
   if (number_of_sub_items > 0)
   {
     PffNodeFolder* mbox = new PffNodeFolder(std::string("Mailbox"), NULL, this);
     this->export_sub_items(pff_root_item, mbox);
     libpff_item_free(&pff_root_item, &(this->pff_error)); 
     this->registerTree(this->parent, mbox);
   }  
}

void pff::initialize(Node* parent)
{
  libbfio_handle_t 	*handle = NULL;
  libbfio_error_t	*error = NULL; 

  this->pff_file = NULL;
  this->pff_error = NULL;
  if (libpff_file_initialize(&(this->pff_file), &(this->pff_error)) != 1)
    throw vfsError(std::string("Unable to initialize system values."));
  if (dff_libbfio_file_initialize(&handle, &error, parent) != 1)
    throw vfsError(std::string("Can't initialize libbfio wrapper for dff"));
  if (libpff_file_open_file_io_handle(this->pff_file, handle, LIBPFF_OPEN_READ, &(this->pff_error)) != 1)
    throw vfsError(std::string("Can't open file with libbfio"));
}


int32_t pff::vopen(Node* tnode)
{
  fdinfo*	fi;
  int32_t	fd;

  PffNodeData* node = dynamic_cast<PffNodeData *>(tnode);

  if (node == NULL)
  {
    PffNodeUnallocatedBlocks* pnode  = dynamic_cast<PffNodeUnallocatedBlocks *>(tnode); 
    if (pnode)
	 return (mfso::vopen(pnode));
    return (-1);
  }
  if (!node->size())
    return (-1);
 
  fi = node->vopen();
  if (fi == NULL)
    return (-1);
 
  fd = this->__fdmanager->push(fi);
  return (fd);
}

int32_t  pff::vread(int fd, void *buff, unsigned int size)
{
  fdinfo*				fi;
  try
   {
     fi = this->__fdmanager->get(fd);
   }
   catch (vfsError e)
   {
     return (0); 
   }
   PffNodeData* node = dynamic_cast<PffNodeData *>(fi->node);
   if (node == NULL)
   {
      if (dynamic_cast<PffNodeUnallocatedBlocks *>(fi->node))
	 return (mfso::vread(fd, buff, size));
      return (0);
   }
   return (node->vread(fi, buff, size));
}

int32_t pff::vclose(int fd)
{
  fdinfo*		fi;
  PffNodeData*		node;

  try
  {
    fi = this->__fdmanager->get(fd);
    node = dynamic_cast<PffNodeData* >(fi->node);
    PffNodeData* node = dynamic_cast<PffNodeData *>(fi->node);
    if (node == NULL)
    {
      if(dynamic_cast<PffNodeUnallocatedBlocks *>(fi->node))
	 return (mfso::vclose(fd));
      return (-1);
    }
    node->vclose(fi);
    this->__fdmanager->remove(fd);
  }
  catch (vfsError e)
  {
    return (-1); 
  }

  return (0);
}

uint64_t pff::vseek(int fd, uint64_t offset, int whence)
{
  fdinfo*		fi;
  PffNodeData*		node; 

  try
  {
    fi = this->__fdmanager->get(fd);
    node = dynamic_cast<PffNodeData*>(fi->node);
    if (node == NULL)
    {
      if (dynamic_cast<PffNodeUnallocatedBlocks *>(fi->node)) 
	 return (mfso::vseek(fd, offset, whence));
      return ((uint64_t) -1);
    }
    return (node->vseek(fi, offset, whence));
  }
  catch (vfsError e)
  {
    return ((uint64_t) -1);
  }
  
  return ((uint64_t) -1);
}

uint64_t	pff::vtell(int32_t fd)
{
  fdinfo*	fi;

  try
  {
      fi = this->__fdmanager->get(fd);
      return (fi->offset);
  }
  catch (vfsError e)
  {
      return (uint64_t)-1; 
  }
}

uint32_t pff::status(void)
{
  return (0);
}
