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

#ifndef __value_hh__
#define __value_hh__

#include "registry_common.hpp"

using namespace Destruct;

class RegistryValues : public DCppObject<RegistryValues>
{
public:
          RegistryValues(DStruct* dstruct, DValue const& args);
          ~RegistryValues();
  DValue  deserializeRaw(DValue const& stream);


  RealValue<DInt32>          size;
  RealValue<DObject*>        parent, list;

  attributeCount(RegistryValues, 3)
  attributeList(attribute(DInt32, size)
                attribute(DObject, list)
                function(DUInt8, deserializeRaw, DObject)
               )
  memberList(RegistryValues, 
             member(RegistryValues, size)
             member(RegistryValues, list)
             method(RegistryValues, deserializeRaw)
            )
private:
  uint64_t                           __size;
  RealValue<DFunctionObject*>        _deserializeRaw;
};

class RegistryValue : public DCppObject<RegistryValue>
{
public:
          RegistryValue(DStruct* dstruct, DValue const& args);
          ~RegistryValue();
  DValue  deserializeRaw(DValue const& stream);
 
  RealValue<DUInt8>          unknown;
  RealValue<DUInt16>         signature, nameLength, named, unknown1, unknown2, valueType;
  RealValue<DInt32>          size, dataOffset, dataLength, dataType;
  RealValue<DObject*>        name, data;

  attributeCount(RegistryValue, 10)
  attributeList(
                attribute(DInt32, size)
                attribute(DUInt16, signature)
                attribute(DUInt16, nameLength)
                attribute(DUInt32, dataLength)
                attribute(DUInt32, dataOffset)
                attribute(DUInt32, dataType)//XXX data in offset ? for 'big data'
                attribute(DUInt16, valueType)
                attribute(DUInt16, unknown1)
                attribute(DObject, name)
                attribute(DObject, data)
                //function(DUInt8, deserializeRaw, DObject)
               )

  memberList(RegistryValue, 
             member(RegistryValue, size)
             member(RegistryValue, signature)
             member(RegistryValue, nameLength)
             member(RegistryValue, dataLength)
             member(RegistryValue, dataOffset)
             member(RegistryValue, dataType)
             member(RegistryValue, valueType)
             member(RegistryValue, unknown1)
             member(RegistryValue, name)
             member(RegistryValue, data)
             //method(RegistryValue, deserializeRaw)
            )
private:
  uint64_t                           __size;
  RealValue<DFunctionObject*>        _deserializeRaw;

  static std::string registryType(uint32_t dataType)
  {
    static std::string registryType[] = { 
                                          "REG_NONE",
                                          "REG_SZ",
                                          "REG_EXPAND_SZ",
                                          "REG_BINARY",
                                          "REG_DWORD",
                                          "REG_DWORD_BIG_ENDIAN",
                                          "REG_LINK",
                                          "REG_MULTI_SZ",
                                          "REG_RESOURCE_LIST",
                                          "REG_FULL_RESOURCE_DESCRIPTON",
                                          "REG_RESOURCE_REQUIEREMENTS_LIST",
                                          "REG_QDWORD",
                                        }; 
    return registryType[dataType]; 
  }
};


class RegistryValueData : public DCppObject<RegistryValueData>
{
public:
          RegistryValueData(DStruct* dstruct, DValue const& args);
          ~RegistryValueData();

  DValue  deserializeRaw(DValue const& stream);


  attributeCount(RegistryValueData, 1)
  attributeList(
                function(DUInt8, deserializeRaw, DObject)
               )
  memberList(RegistryValueData, 
             method(RegistryValueData, deserializeRaw)
            )
private:
  RealValue<DFunctionObject*>        _deserializeRaw; 
};

#endif
