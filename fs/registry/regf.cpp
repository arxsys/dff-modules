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
#include <iostream>

#include "regf.hpp"
#include "registryopt.hpp"

#include "vtime.hpp"
#include "destruct.hpp"

using namespace Destruct;

/**
 *  Regf
 */
Regf::Regf(DStruct* dstruct, DValue const& args) : DCppObject<Regf>(dstruct, args)
{
  this->init();

  this->regfName = new RegfName(Destruct::Destruct::instance().find("RegfName"), RealValue<DObject*>(DNone));
  this->timestamp = new RegfTime64(Destruct::Destruct::instance().find("RegfTime64"), RealValue<DObject*>(DNone));


  ((DObject*)this->regfName)->addRef();
  ((DObject*)this->timestamp)->addRef();
}

Regf::~Regf(void)
{
}

DValue  Regf::validate(void)
{
  if (((DUInt32)this->regf) == 0x66676572 && (this->sequence1 == this->sequence2))
    return (RealValue<DUInt8>(1));
  return (RealValue<DUInt8>(0));
}

DValue  Regf::name(void)
{
  return (((DObject*)this->regfName)->getValue("filename"));
}

DValue  Regf::time(void)
{
  return (((DObject*)this->timestamp)->call("date"));
}

DValue  Regf::version(void)
{
  std::stringstream stringStream;
  stringStream << minor << "." << major;

  return RealValue<DUnicodeString>(stringStream.str());
}

//dDValue  Regf::key(void)
//{
//return  RealValue<DObject*>(new RegistryKey(Destruct::Destruct::instance().find("RegistryKey"), RealValue<DObject*>(DNone)));
//}
/**
 *  RegfTime
 */ 
RegfTime64::RegfTime64(DStruct* dstruct, DValue const& args) : DCppObject<RegfTime64>(dstruct, args)
{
  this->init();
}

RegfTime64::RegfTime64(RegfTime64 const& copy): DCppObject<RegfTime64>(copy)
{
  this->init();
}

RegfTime64::~RegfTime64()
{
}

DValue RegfTime64::date(void)
{
  std::stringstream stringStream;
  vtime* t = new vtime(this->timeStamp, TIME_MS_64);
  
  stringStream << "time " << t->hour << ":" << t->minute << ":" << t->second << " " << t->day << "/" << t->month << "/" << t->year;
  delete t;
  return RealValue<DUnicodeString>(stringStream.str());
}

DValue RegfTime64::deserializeRaw(DValue const& value)
{
  DStream* stream = static_cast<DStream*>(value.get<DObject*>());
  this->timeStamp.unserialize(*stream);
  stream->destroy();

  return (RealValue<DUInt8>(1));
}

/**
 *  RegfName
 */
RegfName::RegfName(DStruct* dstruct, DValue const& args) : DCppObject<RegfName>(dstruct, args)
{
  this->init();
}

RegfName::~RegfName(void)
{
}

DValue    RegfName::deserializeRaw(DValue const& arg)
{
  DStream* stream = static_cast<DStream*>(arg.get<DObject*>());

  char fileNameBuff[60];
  stream->read(fileNameBuff, 60);
  stream->destroy();

  uint32_t i = 0;
  for (; i < 58; ++i)
  {
     if (!(i % 2))
       if (fileNameBuff[i] == 0 && fileNameBuff[i+1] == 0)
         break;
  }
  if (i < 58)
    this->fileName = std::string(fileNameBuff, i);

  return (RealValue<DUInt8>(1));
}
