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
#  Frederic Baguelin <fba@digital-forensic.org>


FIND_PACKAGE(SWIG REQUIRED)
INCLUDE(${SWIG_USE_FILE})

include_directories(${PYTHON_INCLUDE_PATH})

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_HOME_DIRECTORY}/dff/api/include)
include_directories(${CMAKE_HOME_DIRECTORY}/dff/api/tree)
include_directories(${ICU_INCLUDE_DIRS})

set(fat_srcs
  fatfs.cpp
  bootsector.cpp
  fat.cpp
  fattree.cpp
  fatnodes.cpp
  entries.cpp
)


SET_SOURCE_FILES_PROPERTIES(fatfs.i PROPERTIES CPLUSPLUS ON)
SWIG_ADD_MODULE(FATFS python fatfs.i ${fat_srcs})
SWIG_LINK_LIBRARIES(FATFS ${PYTHON_LIBRARIES} ${ICU_LIBRARIES} exceptions types vfs tree)

if ( CMAKE_GENERATOR MATCHES "Visual Studio")
set_target_properties (${SWIG_MODULE_FATFS_REAL_NAME} PROPERTIES
  SUFFIX ".pyd"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_CURRENT_BINARY_DIR}"
)
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")

set(fat_files
  FATFS.py
)

install_lib(${SWIG_MODULE_FATFS_REAL_NAME})
install_file(fat ${fat_files})
