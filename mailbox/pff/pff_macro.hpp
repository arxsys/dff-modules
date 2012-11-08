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

#ifndef __PFF_MACRO_HH__
#define __PFF_MACRO_HH__

#include "pff_common.hpp"

struct libpff_macro_t
{
  uint8_t		type;
  const char* 		message;
} typedef libpff_macro_s;

struct libpff_macro32_t
{
  uint32_t		type;
  const char* 		message;
} typedef libpff_macro32_s;

#define check_maximum_size(func) \
  result = func(item, &entry_value_string_size, (this->pff_error)); \
  if (result != 0 && result != -1) \
  {\
    if (entry_value_string_size > maximum_entry_value_string_size)\
  	maximum_entry_value_string_size = entry_value_string_size;\
  }

#define value_string_to_attribute(func, key) \
  result = func(item, (uint8_t *)entry_value_string, \
maximum_entry_value_string_size, this->pff_error); \
  if (result != -1 && result != 0) \
    (*attr)[key] = new Variant(std::string(entry_value_string));

#define value_time_to_attribute(func, key) \
  result = func(item, &entry_value_64bit, this->pff_error); \
  if (result != -1 && result != 0) \
  { \
     vtime* 	value_time = new vtime(entry_value_64bit, TIME_MS_64); \
     Variant*  variant_time = new Variant(value_time); \
     (*attr)[key] = variant_time; \
  }

#define value_uint32_to_attribute(func, key) \
  result = func(item, &entry_value_32bit, this->pff_error); \
  if (result  != -1 && result != 0) \
  {\
     (*attr)[key] = new Variant(entry_value_32bit); \
  }

#define error_on_item(error_value, Item_index, Parent)\
  std::ostringstream error_name;\
  error_name << "Error on " << Parent->name() << " item " << Item_index + 1;\
  this->res[error_name.str()] = new Variant(std::string(error_value));

#endif
