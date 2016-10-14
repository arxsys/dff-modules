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

from time import strptime

from dff.api.module.script import Script 
from dff.api.module.module import Module
from dff.api.module.manager import ModuleProcessusHandler
from dff.api.types.libtypes import Variant, VMap, VList, Argument, typeId, DateTime 
from dff.api.vfs.libvfs import AttributesHandler, VFS
from popplerqt4 import Poppler

import datetime, sys, traceback

from threading import Lock

def error():
   err_type, err_value, err_traceback = sys.exc_info()
   for n in  traceback.format_exception_only(err_type, err_value):
     print n
   for n in traceback.format_tb(err_traceback):
     print n

class PDFHandler(AttributesHandler):
  def __init__(self):
    AttributesHandler.__init__(self, "metapdf")
    self.pdfnodes = {}  
    self.vfs = VFS.Get()
    self.lock = Lock()
    self.__disown__()
 
  def update(self, processus):
     pass
 
  def setAttributes(self, node):
     #self.pdfnodes.append(node.uid()) 
    try:
      self.pdfnodes[node.uid()] = self.getAttributes(node)
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

  def getAttributes(self, node):
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
        attr["hasJavaScripts"] = (len(doc.scripts()) != 0)
      attr["pages"] = doc.numPages()
      major, minor = doc.getPdfVersion()
      attr["version"] = str(major) + "." + str(minor)
      attr["isEncrypted"] = doc.isEncrypted()
    except Exception as e:
      pass
      #print "metapdf error getting info ", e, " on ", node.absolute()
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

class MetaPDF(Script):
  def __init__(self):
   Script.__init__(self, "metapdf")
   self.handler = PDFHandler() 

  def start(self, args):
    try:
      node = args['file'].value()
      #attr = self.handler.haveMeta(node)
      #if attr == True:
      self.stateinfo = "Registering node: " + str(node.name())
      self.handler.setAttributes(node)
      node.registerAttributes(self.handler)
    except Exception as e:
      print "metapdf error on node ", str(node.absolute()) , " :"
      print str(e)
      pass

class metapdf(Module): 
  """This module parses and sets as node's attributes pdf metadata"""
  def __init__(self):
    Module.__init__(self, "metapdf", MetaPDF)
    self.conf.addArgument({"name": "file",
                           "description": "Parses metadata of this file",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["document/pdf"]})
    self.flags = ["single"]
    self.icon = ":pdf"
    self.tags = "Metadata"
