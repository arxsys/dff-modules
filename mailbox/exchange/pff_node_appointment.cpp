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

#include "pff.hpp"

PffNodeAppointment::PffNodeAppointment(std::string name, Node* parent, pff* fsobj, ItemInfo* itemInfo) : PffNodeEMail(name, parent, fsobj, itemInfo)
{
  int                   result;
  libpff_error_t*       pff_error = NULL;
  libpff_item_t*        item = NULL;
  this->setFile();

//useless for test only 
  result = libpff_file_get_item_by_identifier(this->__pff()->pff_file(), itemInfo->identifier(), &item, &pff_error);
  if (result == 0 || result == -1)
    check_error(pff_error) 
//
  if (libpff_item_free(&item, &pff_error) != 1)
    check_error(pff_error) 
}

std::string PffNodeAppointment::icon(void)
{
  return (":appointment");
}

void  PffNodeAppointment::attributesAppointment(Attributes* attr, libpff_item_t* item)
{
  libpff_error_t* pff_error                     = NULL;
  char*		entry_value_string 		= NULL;
  size_t	entry_value_string_size         = 0;
  size_t	maximum_entry_value_string_size	= 1;
  uint64_t	entry_value_64bit               = 0;
  uint32_t	entry_value_32bit               = 0;
  int 		result                          = 0;

  check_maximum_size(libpff_appointment_get_utf8_location_size)
  check_maximum_size(libpff_appointment_get_utf8_recurrence_pattern_size) 

  if (maximum_entry_value_string_size == 0)
	return ;
  entry_value_string = (char *)malloc(sizeof(char *) * maximum_entry_value_string_size);
  if (entry_value_string == NULL)
     return ;

  value_time_to_attribute(libpff_appointment_get_start_time, "Start time")
  value_time_to_attribute(libpff_appointment_get_end_time, "End time")
  value_uint32_to_attribute(libpff_appointment_get_duration, "Duration")
  value_string_to_attribute(libpff_appointment_get_utf8_location, "Location")
  value_string_to_attribute(libpff_appointment_get_utf8_recurrence_pattern, "Recurrence pattern")
  value_time_to_attribute(libpff_appointment_first_effective_time, "First effective time")
  value_time_to_attribute(libpff_appointment_last_effective_time,  "Last effective time")
  value_uint32_to_attribute(libpff_appointment_get_busy_status, "Busy status")

  free(entry_value_string);

}


Attributes PffNodeAppointment::_attributes()
{
  Attributes		attr;
  libpff_item_t*	item = NULL;
  libpff_error_t*       pff_error = NULL;

  item = this->__itemInfo->item(this->__pff()->pff_file());
  if (item == NULL)
     return attr;

  attr = this->allAttributes(item);

  Attributes	appointment;
  this->attributesAppointment(&appointment, item); 
  attr[std::string("Appointment")] = new Variant(appointment);

  if (libpff_item_free(&item, &pff_error) != 1)
    check_error(pff_error) 

  return attr;
}

