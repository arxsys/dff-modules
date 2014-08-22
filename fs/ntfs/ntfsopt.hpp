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

#ifndef __NTFS_NTFSOPT_HH__
#define __NTFS_NTFSOPT_HH__

#include "ntfs_common.hpp"

#include "protocol/dcppobject.hpp"

class NTFSOpt : public Destruct::DCppObject<NTFSOpt>
{
public:
                NTFSOpt(Attributes args, Destruct::DStruct* dstruct);
                NTFSOpt(Destruct::DStruct* dstruct, Destruct::DValue const& args);
                ~NTFSOpt();
  Node*         fsNode(void) const;
  bool          recovery(void) const;
  std::string   driveName(void) const;
  bool          validateBootSector(void) const;
  bool          advancedAttributes(void) const;

  static size_t ownAttributeCount()
  {
    return (5);
  }

  static Destruct::DAttribute* ownAttributeBegin()
  {
    static Destruct::DAttribute  attributes[] = 
    {
      Destruct::DAttribute(Destruct::DType::DUInt8Type, "validateBootSector"),
      Destruct::DAttribute(Destruct::DType::DUInt8Type, "recovery"),
      Destruct::DAttribute(Destruct::DType::DUInt8Type, "advancedAttributes"),
      Destruct::DAttribute(Destruct::DType::DUnicodeStringType, "driveName"),
      Destruct::DAttribute(Destruct::DType::DObjectType, "fsNode"),
      //report 
    };
    return (attributes);
  }

  static Destruct::DPointer<NTFSOpt>* memberBegin()
  {
    static Destruct::DPointer<NTFSOpt> memberPointer[] = 
    {
      Destruct::DPointer<NTFSOpt>(&NTFSOpt::__validateBootSector),
      Destruct::DPointer<NTFSOpt>(&NTFSOpt::__recovery),
      Destruct::DPointer<NTFSOpt>(&NTFSOpt::__advancedAttributes),
      Destruct::DPointer<NTFSOpt>(&NTFSOpt::__driveName),
      Destruct::DPointer<NTFSOpt>(&NTFSOpt::__fsNode),
    };
    return (memberPointer);
  }

  static Destruct::DAttribute* ownAttributeEnd()
  {
    return (ownAttributeBegin() + ownAttributeCount());
  }

  static Destruct::DPointer<NTFSOpt >*  memberEnd()
  {
    return (memberBegin() + ownAttributeCount());
  }
 

private:
  //Node*                                          __fsNode;
  Destruct::RealValue<DUInt8>                    __validateBootSector;
  Destruct::RealValue<DUInt8>                    __recovery;
  Destruct::RealValue<DUInt8>                    __advancedAttributes;
  Destruct::RealValue<Destruct::DUnicodeString>  __driveName;
  Destruct::RealValue<Destruct::DObject*>        __fsNode;
};

#endif
