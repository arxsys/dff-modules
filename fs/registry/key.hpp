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

#ifndef __key_hh__
#define __key_hh__

#include "registry_common.hpp"

using namespace Destruct;

class RegistryKey: public DCppObject<RegistryKey>
{
public:
          RegistryKey(DStruct* dstruct, DValue const& args);
          ~RegistryKey();

  RealValue<DUInt16> signature, keyType, keyNameLength, classNameLength;
  RealValue<DInt32>  size;
  RealValue<DUInt32> parentKeyOffset, subkeyCount, subkeyCountVolatile,  subkeyListOffset, subkeyListOffsetVolatile, valueCount, valueListOffset,
  securityDescriptorOffset, classNameOffset, unknown1, subkeyNameMaximumLength, subkeyClassNameMaximumLength, valueNameMaximumLength, valueDataMaximumSize, unknown2;
  RealValue<DObject*> keyName, subkeys, values, timestamp;

  RealValue<DUnicodeString>  fileName;


  attributeCount(RegistryKey, 24)
  attributeList(
      attribute(DInt32, size)
      attribute(DUInt16, signature)
      attribute(DUInt16, keyType)
      attribute(DObject, timestamp)
      attribute(DUInt32, unknown1)
      attribute(DUInt32, parentKeyOffset)
      attribute(DUInt32, subkeyCount)
      attribute(DUInt32, subkeyCountVolatile)
      attribute(DUInt32, subkeyListOffset)
      attribute(DUInt32, subkeyListOffsetVolatile)
      attribute(DUInt32, valueCount)
      attribute(DUInt32, valueListOffset)
      attribute(DUInt32, securityDescriptorOffset)
      attribute(DUInt32, classNameOffset)
      attribute(DUInt32, subkeyNameMaximumLength)
      attribute(DUInt32, subkeyClassNameMaximumLength)
      attribute(DUInt32, valueNameMaximumLength)
      attribute(DUInt32, valueDataMaximumSize)
      attribute(DUInt32, unknown2)
      attribute(DUInt16, keyNameLength)
      attribute(DUInt16, classNameLength)
      attribute(DObject, keyName)
      attribute(DObject, subkeys)
      attribute(DObject, values)
      )

  memberList(RegistryKey, 
      member(RegistryKey, size)
      member(RegistryKey, signature)
      member(RegistryKey, keyType)
      member(RegistryKey, timestamp)
      member(RegistryKey, unknown1)
      member(RegistryKey, parentKeyOffset)
      member(RegistryKey, subkeyCount)
      member(RegistryKey, subkeyCountVolatile)
      member(RegistryKey, subkeyListOffset)
      member(RegistryKey, subkeyListOffsetVolatile)
      member(RegistryKey, valueCount)
      member(RegistryKey, valueListOffset)
      member(RegistryKey, securityDescriptorOffset)
      member(RegistryKey, classNameOffset)
      member(RegistryKey, subkeyNameMaximumLength)
      member(RegistryKey, subkeyClassNameMaximumLength)
      member(RegistryKey, valueNameMaximumLength)
      member(RegistryKey, valueDataMaximumSize)
      member(RegistryKey, unknown2)
      member(RegistryKey, keyNameLength)
      member(RegistryKey, classNameLength)
      member(RegistryKey, keyName)
      member(RegistryKey, subkeys)
      member(RegistryKey, values)
      //method(RegistryKey, deserializeRaw)
      )
private:
  RealValue<DFunctionObject*>        _deserializeRaw;
};

class NameLength : public DCppObject<NameLength>
{
public:
          NameLength(DStruct* dstruct, DValue const& args);
          ~NameLength();
  DValue  deserializeRaw(DValue const& stream);

  RealValue<DObject*>        parent;
  RealValue<DUnicodeString>  keyName;
  RealValue<DUnicodeString>  attributeKeyName;

  attributeCount(NameLength, 3)
  attributeList(attribute(DUnicodeString, keyName)
                attribute(DUnicodeString, attributeKeyName)
                function(DUInt8, deserializeRaw, DObject)
                //attribute(DObject, parent) //recurse
               )
  memberList(NameLength, 
             member(NameLength, keyName)
             member(NameLength, attributeKeyName)
             method(NameLength, deserializeRaw)
            )
private:
  uint64_t                           __size;
  RealValue<DFunctionObject*>        _deserializeRaw;
};

class Subkeys : public DCppObject<Subkeys>
{
public:
          Subkeys(DStruct* dstruct, DValue const& args);
          ~Subkeys();
  DValue  deserializeRaw(DValue const& stream);


  RealValue<DInt32>          size;
  RealValue<DUInt16>         signature, subkeyCount;
  RealValue<DObject*>        parent, list;

  attributeCount(Subkeys, 5)
  attributeList(attribute(DInt32, size)
                attribute(DUInt16, signature)
                attribute(DUInt16, subkeyCount)
                attribute(DObject, list)
                function(DUInt8, deserializeRaw, DObject)
               )
  memberList(Subkeys, 
             member(Subkeys, size)
             member(Subkeys, signature)
             member(Subkeys, subkeyCount)
             member(Subkeys, list)
             method(Subkeys, deserializeRaw)
            )
private:
  uint64_t                           __size;
  RealValue<DFunctionObject*>        _deserializeRaw;
};

#endif
