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
#  Solal Jacob <sja@digital-forensic.org>

if(WIN32)
  #find_library(LIBARCHIVE archive PATHS LIBARCHIVE_PATH)
  message("${LIBARCHIVE_PATH}")
  set(archive_files ${LIBARCHIVE_PATH}/libarchive-13.dll;${LIBARCHIVE_PATH}/zlib.dll)
  set(LIBARCHIVE ${LIBARCHIVE_PATH}/libarchive.lib)
  message("${archive_files}")
else (WIN32)
  find_library(LIBARCHIVE archive)
  find_path(LIBARCHIVE_INCLUDE_DIR archive.h)
endif(WIN32)

if (LIBARCHIVE AND LIBARCHIVE_INCLUDE_DIR)
  message(STATUS "Archive library found")
  dff_cpp_module(decompressor
    CPP_FILES decompressor.cpp decompressornode.cpp
    SWIG_FILE decompressor.i
    INCLUDE_DIRS ${ICU_INCLUDE_DIRS} ${LIBARCHIVE_PATH}
    LINK_LIBRARIES ${ICU_LIBRARIES} exceptions types vfs ${LIBARCHIVE}
    EXTRA_FILES ${archive_files}
    )
else (LIBARCHIVE AND LIBARCHIVE_INCLUDE_DIR)
  message(STATUS "Archive library not found")
endif (LIBARCHIVE AND LIBARCHIVE_INCLUDE_DIR)
