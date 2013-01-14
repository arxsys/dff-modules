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
#  Solal Jacob <sja@digital-forensic.org>

set(module_srcs
  __init__.py
)

install_file(module2 ${module_srcs})

add_subdirectory (volumes)
add_subdirectory (fs)
add_subdirectory (builtins)
add_subdirectory (process)
add_subdirectory (search)
add_subdirectory (viewer)
add_subdirectory (phone)
add_subdirectory (statistics)
add_subdirectory (crypto)
add_subdirectory (archives)
add_subdirectory (mem)
add_subdirectory (utils)
add_subdirectory (node)
add_subdirectory (connector)
add_subdirectory (hash)
add_subdirectory (metadata)
add_subdirectory (test)
add_subdirectory (databases)
add_subdirectory (mailbox)
add_subdirectory (export)
