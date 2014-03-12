/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http://www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Solal Jacob <sja@digital-forensic.org>
 */

#include "aff.hpp"
#include "affnode.hpp"

aff::aff() : fso("aff")
{
  mutex_init(&this->__io_mutex);
  this->__fdm = new FdManager();
}

aff::~aff()
{
  mutex_destroy(&this->__io_mutex);
}

void aff::start(std::map<std::string, Variant_p > args)
{
  std::list<Variant_p > vl; 
  std::list<Variant_p >::iterator 		 vpath; 
  AffNode*					 node;

  if (args.find("parent") != args.end())
    this->parent = args["parent"]->value<Node* >();
  else
    this->parent = VFS::Get().GetNode("/");
  if (args.find("path") != args.end())
    vl = args["path"]->value<std::list<Variant_p > >();
  else
    throw(envError("aff module requires path argument"));
  if (args.find("cache size") != args.end())
  {
    std::ostringstream cs;
    cs << args["cache size"]->value<uint32_t >();
    this->cache_size = cs.str(); 
  }
  else
    this->cache_size = "2";
#ifndef WIN32
  setenv("AFFLIB_CACHE_PAGES", this->cache_size.c_str(), 1);
#else
  _putenv_s("AFFLIB_CACHE_PAGES", this->cache_size.c_str());
#endif

  for (vpath = vl.begin(); vpath != vl.end(); vpath++)
  {
     std::string path = (*vpath)->value<Path* >()->path;
     AFFILE* affile = af_open(path.c_str(), O_RDONLY, 0);
     if (affile)
     {
	std::string nname = path.substr(path.rfind('/') + 1);
	node = new AffNode(nname, af_get_imagesize(affile), NULL, this, path, affile);
   	this->registerTree(this->parent, node);   
	this->res[path] = Variant_p(new Variant(std::string("added successfully by aff module")));
     }
     else 
       this->res[path] = Variant_p(new Variant(std::string("can't be added by aff module")));
  }

  return ;

}

int aff::vopen(Node *node)
{
  AffNode* affNode = dynamic_cast<AffNode* >(node);

  if (affNode->affile)
  {
    fdinfo* fi = new fdinfo();
    fi->node = node;
    fi->offset = 0;
    return (this->__fdm->push(fi));
  }
  else
    return (-1);
}

int aff::vread(int fd, void *buff, unsigned int size)
{
  int	 	result;
  fdinfo*	fi;
  AffNode*	affNode = NULL;

  try
  {
     fi = this->__fdm->get(fd);
     affNode = dynamic_cast<AffNode* >(fi->node);
  }
  catch (...)
  {
     return (-1); 
  }

  mutex_lock(&this->__io_mutex);
  af_seek(affNode->affile, (int64_t)fi->offset, SEEK_SET);
  result = af_read(affNode->affile, (unsigned char*)buff, size);
  if (result > 0)
    fi->offset += result;
  mutex_unlock(&this->__io_mutex);

  return (result);
}

int aff::vclose(int fd)
{
  this->__fdm->remove(fd);

  return (0);
}

uint64_t aff::vseek(int fd, uint64_t offset, int whence)
{
  Node*	node;
  fdinfo* fi;

  try
  {
     fi = this->__fdm->get(fd);
     node = fi->node;

     if (whence == 0)
     {
        if (offset <= node->size())
        {
           fi->offset = offset;
           return (fi->offset);
        } 
     }
     else if (whence == 1)
     {
        if (fi->offset + offset <= node->size())
        {
           fi->offset += offset;
	   return (fi->offset);
        }
     }
     else if (whence == 2)
     {
        fi->offset = node->size();
        return (fi->offset);
     }
  }
  catch (...)
  {
     return ((uint64_t) -1);
  }

  return ((uint64_t) -1);
}

uint64_t	aff::vtell(int32_t fd)
{
  fdinfo*	fi;

  try
  {
     fi = this->__fdm->get(fd);
     return (fi->offset);
  }
  catch (...)
  {
     return (uint64_t)-1; 
  }
}

unsigned int aff::status(void)
{
  return (0);
}
