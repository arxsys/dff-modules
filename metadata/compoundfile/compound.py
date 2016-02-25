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
#  Solal Jacob <sja@digital-forensic.org>

__dff_module_prefetch_version__ = "1.0.0"

import datetime, sys, traceback

from dff.api.module.script import Script 
from dff.api.module.module import Module
from dff.api.module.manager import ModuleProcessusHandler
from dff.api.vfs.libvfs import AttributesHandler, VFS, mfso, Node
from dff.api.types.libtypes import Argument, typeId, VMap, Variant

from mscfb import CompoundDocumentHeader
from msoleps import  PropertySetStream
from msdoc import WordDocument
from msoshared import OfficeDocumentSectionCLSID
from msppt import PPT

from olevba import _extract_vba, VBA_Scanner, decompress_stream 

def error():
   err_type, err_value, err_traceback = sys.exc_info()
   for n in  traceback.format_exception_only(err_type, err_value):
     print n
   for n in traceback.format_tb(err_traceback):
     print n

class FakeOle(object):
  def __init__(self):
    pass

  def openstream(self, path):
     node = VFS.Get().GetNode(str(path))
     vfile = node.open()
     return vfile 

class VBANode(Node):
  def __init__(self, name, size, parent, fsobj, attributes):
     Node.__init__(self, name, size, parent, fsobj)
     self.__disown__()
     self.attr  = VMap()
     self.attr["VBA"] = attributes
     self.setTag("suspicious")

  def _attributes(self):
    return self.attr

class CompoundDocumentParser(object):
  def __init__(self, node, largs, mfsobj = None):
     self.node = node
     self.attr = {} 
     self.extraAttr = []
     self.codePage = None
     try :   
        self.cdh = CompoundDocumentHeader(node, mfsobj)
	self.cdh.parseDocument(not 'no-extraction' in largs)
     except :
	error()
	raise Exception("Can't parse document")
     streams = self.cdh.streams()
     for stream in streams:
        if stream.objectType =="StorageObject":
          if stream.objectName == "VBA":
           try:
             hasSuspiscious = None
              #CHECK FOR OTHER TYPE in .doc #add for zip too ?
             #TRY CATCH AT EVERY STEP PLEASE & add options parse vba 
             #gere le mode sans extraction mais avec les metadata 
             children = stream.children()
             for childStream in children:
               if childStream.name() == "dir":
                 dir_path = childStream
             vba_root = stream.parent()
             project_path = None
             children = vba_root.children()
             for childStream in children:
                if childStream.name() == "PROJECT":
                  project_path = childStream
             result = _extract_vba(FakeOle(), vba_root.absolute() + "/", project_path.absolute(), dir_path.absolute())
             for streamPath, fileName, vbaDecompressed, compressedOffset in result:
               hasSuspiscious = True
               scanner = VBA_Scanner(vbaDecompressed)
               scanner.scan()
               name = fileName[:-4]
               children = stream.children()
               for child in  streams:
                  if child.name() == name:
                    vbaStream = child
               attributesMap = VMap() 
               for (detectionType, keyword, desc,)  in  scanner.results:
                 attributesMap[str(detectionType)] = Variant(str(keyword))
               uncompressedSize = vbaStream.size() - compressedOffset
               if uncompressedSize > 0:
                 vbanode = VBANode(str(name) + ".vba", vbaStream.size() - compressedOffset, vbaStream, mfsobj, attributesMap)
                 mfsobj.setVBACompressed(vbanode, compressedOffset)
               #IF NOT CREATE VBA DECOMPRESS
               #vbaStream.setExtraAttributes(("VBA", attributesMap))
               #vbaStream.setTag("suspicious")
             if hasSuspiscious:
              self.node.setTag("suspicious")
             #setnodesuspicous
           except:
             print "VBA analyzer error : \n", error()
	elif stream.objectType == "StreamObject":
	  try:
	     if stream.objectName == "WordDocument":
	       if not 'no-extraction' in largs:
	         wd = WordDocument(stream)
	         if not 'no-text' in largs:
	           wd.createTextNodes()
	         if not 'no-pictures' in largs:
	           wd.createPictureNodes()
	     elif stream.objectName == "Pictures":
	       if not ('no-pictures' in largs or 'no-extraction' in largs):
	         ppt = PPT(stream)
	         ppt.createPictureNodes()
	     else:
               #check if vba macro avec le header ? ou passe direc t et fait un for 
	       propertySet = PropertySetStream(stream, OfficeDocumentSectionCLSID.keys())
	       for clsid in OfficeDocumentSectionCLSID.iterkeys():
	          section = propertySet.sectionCLSID(clsid)
	          if section:
		    (sectionName, sectionIDS) = OfficeDocumentSectionCLSID[clsid]
		    mattr = VMap() 
	            for k, v in sectionIDS.iteritems():
		       Property = section.PropertyList.propertyID(k)
		       if Property and Property.Variant.Value:
		         p = section.PropertyList.propertyID(k).Variant.Value
		         if p and isinstance(p, Variant): #Thumbnail is type node
			   if v == 'Total editing time': #special case see msoshared.py
			     p = Variant(str(datetime.timedelta(seconds=(p.value()/10000000))))
                           elif v == 'Code page':
                             codePage = p.value()
                             if isinstance(codePage, long):
                               self.codePage = 'cp' + str(codePage)
                           elif self.codePage and (v == "Title" or v == "Subject" or v == "Author" or v == "Comments" or v == "Last Author"):
                             p = Variant(p.value().decode(self.codePage).encode('UTF-8'))
			   else:
			     p = Variant(p)
			   mattr[v] =  p
		    stream.setExtraAttributes((sectionName, mattr,))
		    if not 'no-root_metadata' in largs:	
  		      self.extraAttr.append((sectionName, stream.parent().name(), mattr,))
	  #except RuntimeError, e: #not a PropertySetStream
	    #pass	 
          except :
            pass
	    #error()
        if not 'no-extraction' in largs:
	  del stream 
 
  def _attributes(self):
     vmap = VMap()
     vmap["Compound document"] = self.cdh._attributes()
     for (name, parent, attr) in self.extraAttr:
	vmap[name + ' (' + parent + ')'] = attr
     return vmap	

class MetaCompoundHandler(AttributesHandler, ModuleProcessusHandler):
  def __init__(self):
    AttributesHandler.__init__(self, "metacompound")
    ModuleProcessusHandler.__init__(self, "metacompound")
    self.__disown__()
    self.nodeAttributes = {}
    self.vfs = VFS.Get()
 
  def setAttributes(self, node, classAttributes):
    self.nodeAttributes[node.uid()] = classAttributes 

  def update(self, processus):
    pass

  def nodes(self, root):
    nodes = []
    rootAbsolute = root.absolute()
    for node in self.nodeAttributes.keys():
      node = self.vfs.getNodeById(node)
      if node.absolute().find(rootAbsolute) == 0:
	nodes.append(node)
    return nodes

  def attributes(self, node):
    try:
      classAttributes = self.nodeAttributes[node.uid()]
      return classAttributes._attributes()
    except KeyError:
      attr = VMap()
      attr.thisown = False
      return attr

class MetaCompound(mfso):
  def __init__(self):
   mfso.__init__(self, 'metacompound')
   self.__disown__()
   self.handler = MetaCompoundHandler()
   self.vbaCompressed = {}

  def setVBACompressed(self, node, offset):
    self.vbaCompressed[node.uid()] = offset

  def start(self, args):
    try:
      largs = []
      node = args['file'].value()	
      for arg in ['no-extraction', 'no-text', 'no-pictures', 'no-root_metadata']:
	try:
	  value =  args[arg].value()
	  if value:
	    largs.append(arg)
	except IndexError:
	  pass
      self.stateinfo = "Registering node: " + str(node.name())
      p = CompoundDocumentParser(node, largs, self)
      self.handler.setAttributes(node, p)
      node.registerAttributes(self.handler)
      self.stateinfo = ""
    except (KeyError, Exception):
      self.stateinfo = "Error"

  def vread(self, fd, buff, size):
    try:
      fdmanager = self._mfso__fdmanager
      fi = fdmanager.get(fd)
      try:
        compressedOffset = self.vbaCompressed[fi.node.uid()]
        vfile = fi.node.parent().open()
        vfile.seek(compressedOffset)
        try:
          #check if size to read is neg or 0  
          maxOffset = fi.node.size() - fi.offset
          if maxOffset <= 0:
            return (0, "")
          endOffset = fi.offset + size
          if endOffset > fi.node.size():
            endOffset  = maxOffset
          fi.node.size() 
          decomp = decompress_stream(vfile.read())
          decomp = decomp[fi.offset:endOffset]
          vfile.close()
          sizeRead = endOffset - fi.offset
          fi.offset += sizeRead 
          return (sizeRead, decomp)
        except Exception as e:
          print 'decompress error\n', e
          return (0, "")
      except:
        return (mfso.vread(self, fd, buff, size),)
    except Exception as e:
      return (0, "")


class compound(Module): 
  """This module extracts metadata and content of compound files (doc,xls,msi, ...)"""
  def __init__(self):
    Module.__init__(self, "compound", MetaCompound)
    self.conf.addArgument({"name": "file",
                           "description": "Extract metadata and content of this file",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "compatible extension",
 	                   "values": ["windows/compound", "document/word", "document/excel", "document/powerpoint"]})
    self.conf.addArgument({"name": "no-extraction",	
			   "description" : "Don't create nodes for files stored inside compound documents",
			   "input": Argument.Empty})
    self.conf.addArgument({"name": "no-text",	
			   "description" : "Don't extract text from word document",
			   "input": Argument.Empty})
    self.conf.addArgument({"name": "no-pictures",	
			   "description" : "Don't extract pictures from word and powerpoint documents",
			   "input": Argument.Empty})
    self.conf.addArgument({"name" : "no-root_metadata",
			   "description" : "Don't apply metadata on the root document",
			   "input": Argument.Empty})
    #self.flags = ["single"]
    self.tags = "Metadata"
    self.icon = ":document.png"
