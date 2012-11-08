# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2011 ArxSys
#
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
#  Christophe Malinge <cma@digital-forensic.org>

FIND_PACKAGE(SWIG REQUIRED)
INCLUDE(${SWIG_USE_FILE})

include_directories(${PYTHON_INCLUDE_PATH})

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_HOME_DIRECTORY}/dff/api/include)
include_directories(${ICU_INCLUDE_DIRS})

#add_definitions(-Wall -Wunused -Wextra)

set(ntfs_srcs
  ntfs.cpp
  boot.cpp
  mftentry.cpp
  mftfile.cpp
  attribute.cpp
  ntfsnode.cpp
  attributes/data.cpp
  attributes/bitmap.cpp
  attributes/filename.cpp
  attributes/standardinformation.cpp
  attributes/attributelist.cpp
  attributes/indexroot.cpp
  attributes/reparsepoint.cpp
  attributes/indexallocation.cpp
  attributes/securitydescriptor.cpp
)

SET_SOURCE_FILES_PROPERTIES(ntfs.i PROPERTIES CPLUSPLUS ON)
SWIG_ADD_MODULE(NTFS python ntfs.i ${ntfs_srcs})
SWIG_LINK_LIBRARIES(NTFS ${PYTHON_LIBRARIES} ${ICU_LIBRARIES} exceptions types vfs)

if ( CMAKE_GENERATOR MATCHES "Visual Studio")
set_target_properties (${SWIG_MODULE_NTFS_REAL_NAME} PROPERTIES
  SUFFIX ".pyd"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_CURRENT_BINARY_DIR}"
)
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")

set(ntfs_files
  NTFS.py
)

install_lib(${SWIG_MODULE_NTFS_REAL_NAME})
install_file(ntfs ${ntfs_files})
