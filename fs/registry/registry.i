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
 
%include "windows.i"
%include "exception.i"

%{
#include "exceptions.hpp"
#include "registry.hpp"
%}

%import "../../../api/vfs/libvfs.i"

%ignore Registry::open;
%ignore Registry::createNodeTree;
%ignore Registry::createKeyNode;

%include "registry.hpp"

%pythoncode
%{
from dff.api.module.module import * 
from dff.api.types.libtypes import * 

class registry(Module):
  def __init__(self):
    Module.__init__(self, 'registry', Registry)
    self.conf.addArgument({"name": "file",
                           "description": "Path to a file containing windows registry",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name": "mime-type", 
                           "type": typeId.String,
                           "description": "managed mime type",
                           "values": ["windows/registry"]})
    self.conf.description = "Expand windows registry tree."
    self.tags = "File systems"
    self.flags = ["noscan"]
    self.scanFilter = 'path in [$*Users*$, $*Documents and Settings*$] and name matches "NTUSER.DAT" or path matches $*system32/config*$'
    self.icon = ":password.png"
%}
