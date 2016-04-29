# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
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
# 

__dff_module_documentviewer_version__ = "1.0.0"

from dff.api.module.module import Module
from dff.api.module.script import Script
from dff.api.types.libtypes import Argument, typeId

from documentconverter import DocumentConverter
from pdfwidget import PDFWidget

class DocumentViewer(PDFWidget, Script):
  def __init__(self):
    Script.__init__(self, "Document viewer")
    self.name = "Document viewer"
    self.thread = None

  def start(self, args):
    self.node = args["file"].value()
    try:
      self.preview = args["preview"].value()
    except IndexError:
      self.preview = False

  def __del__(self):
     if self.thread:
       print 'deleting  my self waiting for thread en', str(self.node.absolute())
       self.thread.wait()
       print 'thread wait finish'
       #PDFWidget.close(self) 

  def g_display(self):
    PDFWidget.__init__(self)
    if self.node.dataType() == "document/pdf":
      vfile = self.node.open()
      pdfDocument = vfile.read()
      vfile.close()
    else:
      self.converter = DocumentConverter() 
      pdfDocument = self.converter.convert(self.node)
    self.setDocument(pdfDocument)

  def updateWidget(self):
	pass

class documentviewer(Module):
  """Document viewer"""
  def __init__(self):
    Module.__init__(self, "Document viewer", DocumentViewer)
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Node,
                           "name": "file",
                           "description": "File to display"})
    self.conf.addArgument({"name": "preview",
			   "description": "Preview mode",
			   "input": Argument.Empty})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "type of file compatible with this module",
 	                   "values": ["document", "windows/compound"]})
    self.tags = "Viewers"
    self.flags = ["gui"]
    self.icon = ":pdf" #change XXX
