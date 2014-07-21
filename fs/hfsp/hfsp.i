/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2013 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http://www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Frederic Baguelin <fba@digital-forensic.org>
 */

#include "pyrun.swg"

%module  HFSP

%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "std_vector.i"
%include "windows.i"

%{
#include "variant.hpp"
#include "vtime.hpp"
#include "node.hpp"
#include "vlink.hpp"
#include "vfile.hpp"
#include "mfso.hpp"
#include "hfsp.hpp"
#include "rootnode.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%include "hfsp.hpp"

%pythoncode
%{

__dff_module_fatfs_version__ = "1.0.0"

from dff.api.module.module import *
from dff.api.types.libtypes import Argument, typeId

class HFSP(Module):
  """This module create the tree contained in a fat file system, for normal and deleted files."""
  def __init__(self):
    Module.__init__(self, 'hfsp', Hfsp)
    self.conf.addArgument({"name": "file",
                           "description": "file containing a HFS Plus file system",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name": "mime-type",
                           "type": typeId.String,
                           "description": "managed mime type",
			   "values": ["HFS"]})
    self.tags = "File systems"
%}

