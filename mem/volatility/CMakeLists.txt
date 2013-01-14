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

set(volatility_files
  dfwrapper.py
  setup.py
  vmodules.py
  volatility.py
  vsyms.py
  vtypes.py
  vutils.py
)

install_file(_volatility ${volatility_files})

add_subdirectory(memory_objects)
add_subdirectory(memory_plugins)
add_subdirectory(forensics)
add_subdirectory(thirdparty)
