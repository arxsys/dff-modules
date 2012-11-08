# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
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
#  Solal Jacob <sja@digital-forensic.org>


FIND_PACKAGE(SWIG REQUIRED)
INCLUDE(${SWIG_USE_FILE})

include_directories(${PYTHON_INCLUDE_PATH})
include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_HOME_DIRECTORY}/dff/api/include)
include_directories(${EWF_INCLUDE_DIR})

set(ewf_srcs
    ewf.cpp
    ewfnode.cpp
)

SET_SOURCE_FILES_PROPERTIES(ewf.i PROPERTIES CPLUSPLUS ON)
SWIG_ADD_MODULE(EWF python ewf.i ${ewf_srcs})
if(WIN32)
	add_definitions(-D_LIBEWF_TYPES_H_INTEGERS)
	FILE(COPY ${EWF_DYN_LIBRARIES} DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
endif(WIN32)
SWIG_LINK_LIBRARIES(EWF ${PYTHON_LIBRARIES} exceptions types vfs ${EWF_LIBRARY})

if ( CMAKE_GENERATOR MATCHES "Visual Studio")
set_target_properties (${SWIG_MODULE_EWF_REAL_NAME} PROPERTIES
  SUFFIX ".pyd"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_CURRENT_BINARY_DIR}"
)
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")

if(WIN32)
  set(ewf_files
    EWF.py
    libewf.dll
    zlib.dll
  )
else(WIN32)
  set(ewf_files
    EWF.py
  )
endif(WIN32)

install_lib(${SWIG_MODULE_EWF_REAL_NAME})
install_file(ewf ${ewf_files})
