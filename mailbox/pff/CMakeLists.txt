# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2010 ArxSys
# This program is free software, distributed under the terms of
# the GNU General Public License Version 2. See the LICENSE file
# at the top of the source tree.
#  
# See http://www.digital-forensic.org for more information about this
# project. Please do not directly contact any of the maintainers of
# DFF for assistance; the project provides a web site, mailing lists
# and IRC channels for your use.
# 
# Author(s):
#  Frederic Baguelin <fba@digital-forensic.org>
#  Solal Jacob <sja@digital-forensic.org>


FIND_PACKAGE(SWIG REQUIRED)
INCLUDE(${SWIG_USE_FILE})

include_directories(${PYTHON_INCLUDE_PATH})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_HOME_DIRECTORY}/dff/api/include)
include_directories(${PFF_INCLUDE_DIR})
include_directories(${BFIO_INCLUDE_DIR})


set(pff_srcs
    pff.cpp
    pff_info.cpp
    pff_export.cpp
    pff_node_data.cpp
    pff_node_task.cpp
    pff_node_folder.cpp
    pff_node_contact.cpp
    pff_node_attachment.cpp
    pff_node_appointment.cpp
    pff_node_unallocated_blocks.cpp
    pff_node_email.cpp
    pff_node_email_message.cpp
    pff_node_email_attributes.cpp
    pff_node_email_transport_headers.cpp
    libbfio_wrapper.cpp
)

SET_SOURCE_FILES_PROPERTIES(pff.i PROPERTIES CPLUSPLUS ON)
SWIG_ADD_MODULE(PFF python pff.i ${pff_srcs})

if(WIN32)
  add_definitions(-DLIBPFF_HAVE_BFIO -D_LIBPFF_TYPES_H_INTEGERS -D_LIBBFIO_TYPES_H_INTEGERS)
  FILE(COPY ${PFF_DYN_LIBRARIES} ${BFIO_DYN_LIBRARIES} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
  message(STATUS "${BFIO_DYN_LIBRARIES}")
endif(WIN32)

SWIG_LINK_LIBRARIES(PFF ${PYTHON_LIBRARIES} exceptions types vfs ${PFF_LIBRARY} ${BFIO_LIBRARY})

if ( CMAKE_GENERATOR MATCHES "Visual Studio")
set_target_properties (${SWIG_MODULE_PFF_REAL_NAME} PROPERTIES
  SUFFIX ".pyd"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_CURRENT_BINARY_DIR}"
)
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")

if(WIN32)
  set(pff_files
    PFF.py
    libpff.dll
    libbfio.dll
  )
else(WIN32)
  set(pff_files
    PFF.py
  )
endif(WIN32)

install_lib(${SWIG_MODULE_PFF_REAL_NAME})
install_file(pff ${pff_files})
