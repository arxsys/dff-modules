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

#ifndef __regf_hh__
#define __regf_hh__

#include "registry_common.hpp"

using namespace Destruct;

class Regf : public DCppObject<Regf>
{
public:
  RealValue<DUInt32>  regf, sequence1, sequence2, major, minor, unknown1, unknown2,
                                keyrecord, lasthbin, unknown3;
  RealValue<DObject*> regfName, timestamp, key;

  Regf(DStruct* dstruct, DValue const& args);
  ~Regf();
  DValue              name(void);
  DValue              time(void);
  DValue              version(void);
  DValue              validate(void);
  //DValue              key(void);

  attributeCount(Regf, 16)

  attributeList(attribute(DUInt32, regf)
                attribute(DUInt32, sequence1)
                attribute(DUInt32, sequence2)
                attribute(DObject, timestamp)
                attribute(DUInt32, major)
                attribute(DUInt32, minor)
                attribute(DUInt32, unknown1)
                attribute(DUInt32, unknown2)
                attribute(DUInt32, keyrecord)
                attribute(DUInt32, lasthbin)
                attribute(DUInt32, unknown3)
                attribute(DObject, regfName)
                function(DUnicodeString, name, DNone)
                function(DUnicodeString, time, DNone)
                function(DUnicodeString, version, DNone)
                attribute(DObject, key)
                //function(DObject, key, DNone)
               )

  memberList(Regf, 
             member(Regf, regf)
             member(Regf, sequence1)
             member(Regf, sequence2)
             member(Regf, timestamp)
             member(Regf, major)
             member(Regf, minor)
             member(Regf, unknown1)
             member(Regf, unknown2)
             member(Regf, keyrecord)
             member(Regf, lasthbin)
             member(Regf, unknown3)
             member(Regf, regfName)
             method(Regf, name)
             method(Regf, time)
             method(Regf, version)
             member(Regf, key)
             //method(Regf, key)
            )
private:
  RealValue<DFunctionObject*>        _name, _time, _version;//, _key;
};

class RegfName : public DCppObject<RegfName>
{
public:
          RegfName(DStruct* dstruct, DValue const& args);
          ~RegfName();
  DValue  deserializeRaw(DValue const& stream);

  RealValue<DUnicodeString>  fileName;


  attributeCount(RegfName, 2)
  attributeList(attribute(DUnicodeString, fileName)
                function(DUInt8, deserializeRaw, DObject)
               )
  memberList(RegfName, 
             member(RegfName, fileName)
             method(RegfName, deserializeRaw)
            )
private:
  RealValue<DFunctionObject*>        _deserializeRaw;
};

class RegfTime64 : public DCppObject<RegfTime64>
{
public:
          RegfTime64(DStruct* dstruct, DValue const& args);
          RegfTime64(RegfTime64 const& copy);
          ~RegfTime64();
  DValue  deserializeRaw(DValue const& stream);

  DValue date(void);
  RealValue<DUInt64>  timeStamp;

  attributeList(
                attribute(DUInt64, timeStamp)
                function(DUnicodeString, date, DNone)
                function(DUInt8, deserializeRaw, DObject)
               )
  memberList(RegfTime64, 
             member(RegfTime64, timeStamp)
             method(RegfTime64, date)
             method(RegfTime64, deserializeRaw)
            )
  attributeCount(RegfTime64, 3)
private:
  RealValue<DFunctionObject*>        _deserializeRaw;
  RealValue<DFunctionObject*>        _date;
};

#endif
