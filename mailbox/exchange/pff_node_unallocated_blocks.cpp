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

PffNodeUnallocatedBlocks::PffNodeUnallocatedBlocks(std::string name, Node *parent, mfso* fsobj, Node* root, int block_type, libpff_error_t** error, libpff_file_t** file) : Node(name, 0, parent, fsobj)
{
  off64_t offset                   = 0;
  size64_t size                    = 0;
  int number_of_unallocated_blocks = 0;
  int block_iterator               = 0;
  uint64_t  node_size		   = 0;

  this->root = root;
  this->block_type = block_type;
  this->pff_file = file;
  this->pff_error = error;

  if (libpff_file_get_number_of_unallocated_blocks(*(this->pff_file), this->block_type, &number_of_unallocated_blocks, this->pff_error) != 1)
    return ;
  if (block_type == LIBPFF_UNALLOCATED_BLOCK_TYPE_PAGE)
    fsobj->res["Number of unallocated page blocks"] = new Variant(number_of_unallocated_blocks);
  else
    fsobj->res["Number of unallocated data blocks"] = new Variant(number_of_unallocated_blocks);
  

  if (number_of_unallocated_blocks > 0)
  {
     for (block_iterator = 0; block_iterator < number_of_unallocated_blocks; block_iterator++)
     {
	if (libpff_file_get_unallocated_block(*(this->pff_file), this->block_type, block_iterator, &offset, &size, this->pff_error) == 1)
	{
	  node_size += size;	
	}
     }
  } 
  this->setSize(node_size);
}

void	PffNodeUnallocatedBlocks::fileMapping(FileMapping* fm)
{

  off64_t offset                   = 0;
  size64_t size                    = 0;
  int number_of_unallocated_blocks = 0;
  int block_iterator               = 0;
  uint64_t voffset		   = 0;

  if (libpff_file_get_number_of_unallocated_blocks(*(this->pff_file), this->block_type, &number_of_unallocated_blocks, this->pff_error) != 1)
    return ;

  if (number_of_unallocated_blocks > 0)
  {
     for (block_iterator = 0; block_iterator < number_of_unallocated_blocks; block_iterator++)
     {
	if (libpff_file_get_unallocated_block(*(this->pff_file), this->block_type, block_iterator, &offset, &size, this->pff_error) == 1)
	{
	  fm->push(voffset, size, this->root, offset);
	  voffset += size;	
	}
     }
  }
  return ;
}
