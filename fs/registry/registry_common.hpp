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

#ifndef __registry_common_hpp__
#define __registry_common_hpp__

#include <typeinfo>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "destruct.hpp"
#include "drealvalue.hpp"
#include "dvalue.hpp"
#include "dobject.hpp"
#include "dnullobject.hpp"
#include "protocol/dcppobject.hpp"
#include "protocol/dstream.hpp"
#include "protocol/dserialize.hpp"

#include "export.hpp"
#include "vfs.hpp"
#include "mfso.hpp"
#include "node.hpp"
#include "variant.hpp"
#include "typesconv.hpp"

#define registerDCpp(x)\
  Destruct::DStruct* x##Struct = Destruct::makeNewDCpp<x>(#x);\
  destruct.registerDStruct(x##Struct);

#define attribute(type, name)\
  Destruct::DAttribute(Destruct::DType::type##Type, #name),

#define function(returnType, name, argumentType)\
  Destruct::DAttribute(Destruct::DType::returnType##Type, #name, Destruct::DType::argumentType##Type),

#define attributeList(list)\
  static Destruct::DAttribute* ownAttributeBegin()\
  {\
    static Destruct::DAttribute  attributes[] = \
    {\
      list\
    };\
    return (attributes);\
  }\


#define member(klass, name)\
  Destruct::DPointer<klass>(&klass::name),

#define method(klass, n)\
  Destruct::DPointer<klass>(&klass::_##n, &klass::n),

#define attributeCount(klass, count)\
  static size_t ownAttributeCount()\
  {\
    return (count);\
  }\
\
  static Destruct::DAttribute* ownAttributeEnd()\
  {\
    return (ownAttributeBegin() + ownAttributeCount());\
  }\
\
  static Destruct::DPointer<klass>*  memberEnd()\
  {\
    return (memberBegin() + ownAttributeCount());\
  }

#define memberList(klass, list)\
  static Destruct::DPointer<klass>* memberBegin()\
  {\
    static Destruct::DPointer<klass> memberPointer[] = \
    {\
      list\
    };\
    return (memberPointer);\
  }\

#define NEW_VARIANT(x) Variant_p(new Variant(x))
#define MAP_ATTR(x, y) attrs[x] = NEW_VARIANT(y);

#endif 
