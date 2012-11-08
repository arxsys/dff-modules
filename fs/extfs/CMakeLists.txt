# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
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
#  Romain Bertholon <rbe@digital-forensic.org>

FIND_PACKAGE(SWIG REQUIRED)
INCLUDE(${SWIG_USE_FILE})

include_directories(${PYTHON_INCLUDE_PATH})

include_directories(${CMAKE_CURRENT_SOURCE_DIR})
include_directories(${CMAKE_HOME_DIRECTORY}/dff/api/include)
include_directories(${CMAKE_HOME_DIRECTORY}/dff/api/tree)

set(extfs_srcs
  extfs.cpp
  Directory.cpp
  SymLink.cpp
  Journal.cpp
  JournalType.tpp
  FileNameRecovery.cpp
  CustomResults.cpp
  CustomAttrib.cpp
  fsck.cpp
  FsStat.cpp
  InodeStat.cpp
  JournalStat.cpp
  InodesList.cpp
  InodeUtils.cpp
  SuperBlockUtils.cpp
  ExtfsNode.cpp
  ExtfsSlackNode.cpp
  ExtfsRawDataNode.cpp
  ExtfsSymLinkNode.cpp
  BlkList.cpp
  MfsoAttrib.cpp
  Option.cpp
  OrphansInodes.cpp
  data_structure/InodeStructure.cpp
  data_structure/SuperBlock.cpp
  data_structure/GroupDescriptor.cpp
  data_structure/Inode.cpp
  data_structure/DirEntry.cpp
  data_structure/SuperBlockStructure.cpp
  data_structure/ExtendedAttr.cpp
  data_structure/Ext4Extents.cpp
)

SET_SOURCE_FILES_PROPERTIES(extfs.i PROPERTIES CPLUSPLUS ON)
SWIG_ADD_MODULE(EXTFS python extfs.i ${extfs_srcs})
SWIG_LINK_LIBRARIES(EXTFS ${PYTHON_LIBRARIES} exceptions types vfs tree)

if ( CMAKE_GENERATOR MATCHES "Visual Studio")
set_target_properties (${SWIG_MODULE_EXTFS_REAL_NAME} PROPERTIES
  SUFFIX ".pyd"
  RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_CURRENT_BINARY_DIR}"
  RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${CMAKE_CURRENT_BINARY_DIR}"
)
endif ( CMAKE_GENERATOR MATCHES "Visual Studio")

set(extfs_files
  EXTFS.py
)

install_lib(${SWIG_MODULE_EXTFS_REAL_NAME})
install_file(extfs ${extfs_files})
