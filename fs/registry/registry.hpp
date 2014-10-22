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

#ifndef __registry_hpp__
#define __registry_hpp__

#include "registry_common.hpp"

class RegistryOpt;
class Regf;

class Registry : public  mfso, public Destruct::DCppObject<Registry>
{
public:
  Registry();
  ~Registry();

  Registry(Destruct::DStruct* dstruct);
  Registry(Registry const&);

  static void           declare(void);

  void                  start(Attributes args);
  //void                setStateInfo(const std::string&);
  bool                  load(Destruct::DValue value);
  Destruct::DValue      save(void) const;

  static void           show(Destruct::DObject* object);
  static void           toFile(std::string fileName, Destruct::DObject* object, std::string type);

  RegistryOpt*          opt(void) const;
  Regf*                 regf(void) const;
private:
  RegistryOpt*          __opt; 
  Regf*                 __regf;
  Destruct::Destruct&   __destruct;
public:
  static size_t ownAttributeCount()
  {
    return (0);
  }

  static Destruct::DAttribute* ownAttributeBegin()
  {
    static Destruct::DAttribute  attributes[] = 
    {
    };
    return (attributes);
  }

  static Destruct::DPointer<Registry>* memberBegin()
  {
    static Destruct::DPointer<Registry> memberPointer[] = 
    {
    };
    return (memberPointer);
  }

  static Destruct::DAttribute* ownAttributeEnd()
  {
    return (ownAttributeBegin() + ownAttributeCount());
  }

  static Destruct::DPointer<Registry >*  memberEnd()
  {
    return (memberBegin() + ownAttributeCount());
  }
};

#endif
