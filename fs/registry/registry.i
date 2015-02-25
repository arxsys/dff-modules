/* 
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
 * 
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
 *  Solal Jacob <sja@digital-forensic.org>
 */

%module registry
 
%include "std_string.i"
%include "std_list.i"
%include "std_set.i"
%include "std_map.i"
%include "std_vector.i"
%include "windows.i"

//%ignore NTFS::fsNode;

%{
#include "variant.hpp"
#include "vtime.hpp"
#include "node.hpp"
#include "vlink.hpp"
#include "vfile.hpp"
#include "mfso.hpp"
#include "registry.hpp"
#include "rootnode.hpp"
#include "../../../api/destruct/python/py_dvalue.hpp"
%}

%import "../../../api/vfs/libvfs.i"
%import "../../../api/include/dswrapper.i"

%include "registry.hpp"

%pythoncode
%{
from dff.api.module.module import * 
from dff.api.types.libtypes import * 

class registry(Module):
  def __init__(self):
    Module.__init__(self, 'registry', Registry)
    Registry.declare()
    self.conf.addArgument({"name": "file",
                           "description": "Path to a file containing windows registry",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    #self.conf.addConstant({"name": "mime-type",
                           #"description": "mime type value",
                           #"type" : typeId.String,
                           #"values" : ["registry file"]})
    self.conf.description = "Expand windows registry tree."
    self.tags = "File systems"
    self.flags = ["noscan"]
    self.icon = ":password.png"
%}
