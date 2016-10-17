# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
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
#  Frederic Baguelin <fba@digital-forensic.org>
#  Christophe Malinge <cma@digital-forensic.org>

__dff_module_metapdf_version__ = "1.0.0"

import datetime, sys, traceback
from time import strptime
from threading import Lock
from popplerqt4 import Poppler

from dff.api.module.script import Script 
from dff.api.module.module import Module
from dff.api.module.manager import ModuleProcessusHandler
from dff.api.types.libtypes import Variant, VMap, VList, Argument, typeId, DateTime 
from dff.api.vfs.libvfs import AttributesHandler, VFS, mfso, fso, Node, FdManager, fdinfo

def error():
   err_type, err_value, err_traceback = sys.exc_info()
   for n in  traceback.format_exception_only(err_type, err_value):
     print n
   for n in traceback.format_tb(err_traceback):
     print n

class JSNode(Node):
  def __init__(self, name, size, parent, fsobj):
    vfile = parent.open()
    doc = Poppler.Document.loadFromData(vfile.read())
    vfile.close()
    buff = ""
    for script in doc.scripts():
      buff += bytearray(script.toUtf8())
    Node.__init__(self, name, len(buff), None, fsobj)
    self.__disown__()

  def _attributes(self):
    return VMap()

class PDFHandler(AttributesHandler):
  def __init__(self):
    AttributesHandler.__init__(self, "metapdf")
    self.pdfnodes = {}  
    self.vfs = VFS.Get()
    self.lock = Lock()
    self.__disown__()
 
  def update(self, processus):
     pass
 
  def setAttributes(self, node, mfsobj, extractJS = True):
     #self.pdfnodes.append(node.uid()) 
    try:
      self.pdfnodes[node.uid()] = self.getAttributes(node, mfsobj, extractJS)
    except:
      pass

  def attributes(self, node):
    vmap = VMap()
    try:
      attributes = self.pdfnodes[node.uid()]
      for k, v in attributes.iteritems():
        if type(v) == DateTime:
          dt = DateTime(v)
          dt.thisown = False
          vmap[k] = Variant(dt)
        else:
          vmap[k] = Variant(v)
      return vmap
    except:
      return vmap

  def getAttributes(self, node, mfsobj, extractJS = True):
    attr = {} 
    self.lock.acquire()
    try:
      vfile = node.open()
      doc = Poppler.Document.loadFromData(vfile.read())
      vfile.close()
    except Exception as e:
      #print "metapdf can't read document ", e, " on ", node.absolute()
      self.lock.release()
      return attr
    if doc is None:
      self.lock.release()
      return attr
    try:
      isLocked = doc.isLocked()
      attr["isLocked"] = isLocked
      if not isLocked:
        attr["hasEmbeddedFiles"] = doc.hasEmbeddedFiles()
      scripts  = doc.scripts()
      if len(scripts) and extractJS:
         jsnode = JSNode("javascript", 0, node, mfsobj)
         mfsobj.registerTree(node, jsnode)
      attr["hasJavaScripts"] = (len(scripts) != 0)
      attr["pages"] = doc.numPages()
      major, minor = doc.getPdfVersion()
      attr["version"] = str(major) + "." + str(minor)
      attr["isEncrypted"] = doc.isEncrypted()
    except Exception as e:
      #pass
      print "metapdf error getting info ", e, " on ", node.absolute()
    infoKeys = doc.infoKeys()  
    for key in infoKeys:
      try:
        value = doc.info(key)
        ukey = unicode(key.toUtf8(), 'UTF-8').encode('UTF-8')
        uvalue = unicode(value.toUtf8(), 'UTF-8').encode('UTF-8')
        if uvalue[0:2] == "D:":
          uvalue = uvalue[2:16]
          dt = strptime(uvalue, "%Y%m%d%H%M%S")
          vt = DateTime(dt.tm_year, dt.tm_mon, dt.tm_mday, dt.tm_hour, dt.tm_min, dt.tm_sec)
          vt.thisown = False
          uvalue = vt 
        attr[ukey] = uvalue
      except Exception as e:
        pass
        #print "metapdf error getting metadata ", e, " on ", node.absolute()
    self.lock.release()
    return attr

class MetaPDF(fso):
  def __init__(self):
   fso.__init__(self, "metapdf")
   self.__disown__()
   self.handler = PDFHandler() 
   self.fdm = FdManager()

  def start(self, args):
    try:
      node = args['file'].value()
      try:
        extractJs = args['extractJS'].value()
      except IndexError:
        extractJs = False
      #attr = self.handler.haveMeta(node)
      #if attr == True:
      self.stateinfo = "Registering node: " + str(node.name())
      self.handler.setAttributes(node, self, extractJs)
      node.registerAttributes(self.handler)
    except Exception as e:
      print "metapdf error on node ", str(node.absolute()) , " :"
      print str(e)
      pass

  def vopen(self, node):
    if not node.size():
      return 0
    fi = fdinfo()
    fi.thisown = False
    fi.node = node
    fi.offset = 0
    fd = self.fdm.push(fi)
    return fd

  def vread(self, fd, buff, size):
   try:
     fi = self.fdm.get(fd)
     vfile = fi.node.parent().open()
     doc = Poppler.Document.loadFromData(vfile.read())
     vfile.close()
     buff = "" 
     for script in doc.scripts():
       buff += bytearray(script.toUtf8())
     res = str(buff[fi.offset:fi.offset + size])
     fi.offset += len(res)
     return (len(res), res)
   except Exception as e:
     return (0, "")

  def vseek(self, fd, offset, whence):
    fi = self.fdm.get(fd)
    if whence == 0:
      if offset <= fi.node.size():
        fi.offset = offset
    if whence == 1:
      if fi.offset + offset > fi.node.size():
        fi.offset += offset
    if whence == 2:
      fi.offset = fi.node.size()
    return fi.offset

  def vclose(self, fd):
    return 0

  def vtell(self, fd):
    fi = self.fdm.get(fd)

class metapdf(Module): 
  """This module parses and sets as node's attributes pdf metadata"""
  def __init__(self):
    Module.__init__(self, "metapdf", MetaPDF)
    self.conf.addArgument({"name": "file",
                           "description": "Parses metadata of this file",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addArgument({"name": "extractJS",
                           "description": "Extract javascript as node",
                           "input":Argument.Empty})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["document/pdf"]})
    self.flags = ["single"]
    self.icon = ":pdf"
    self.tags = "Metadata"
