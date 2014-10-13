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
                attribute(DInt32, size)         // 0x00
                attribute(DUInt16, signature)   // 0x04 name_length
                attribute(DUInt16, nameLength)  // 0x06 data_size
                attribute(DUInt32, dataLength)  // 0x08 data_offset
                attribute(DUInt32, dataOffset)    // 0xc 
                attribute(DUInt32, dataType)     // 0x10 
                attribute(DUInt16, valueType)   // 0x14 flags
                attribute(DUInt16, unknown1)    // 0x16
                attribute(DObject, name)        // 0x18
                attribute(DObject, data)        //
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
};

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
