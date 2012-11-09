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
include_directories(${CMAKE_HOME_DIRECTORY}/api/include)
include_directories(${ICU_INCLUDE_DIRS})


set(ntfs_srcs
  ntfs.cpp
  ntfsopt.cpp
  bootsector.cpp
  mftentrynode.cpp
  mftattribute.cpp
  mftattributecontent.cpp
  mftnode.cpp
  standardinformation.cpp
  filename.cpp
)

SET_SOURCE_FILES_PROPERTIES(ntfs.i PROPERTIES CPLUSPLUS ON)
SWIG_ADD_MODULE(ntfs python ntfs.i ${ntfs_srcs})
SWIG_LINK_LIBRARIES(ntfs ${PYTHON_LIBRARIES} ${ICU_LIBRARIES} _libexceptions _libtypes _libvfs icui18n)

if ( CMAKE_GENERATOR MATCHES "Visual Studio")
set_target_properties (${SWIG_MODULE_ntfs_REAL_NAME} PROPERTIES
  SUFFIX ".pyd"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_CURRENT_BINARY_DIR}"
)
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")

set(ntfs_files
  ntfs.py
)

install_lib(${SWIG_MODULE_ntfs_REAL_NAME})
install_file(ntfs ${ntfs_files})
