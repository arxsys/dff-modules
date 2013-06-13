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
#  Jeremy MOUNIER <jmo@digital-forensic.org>
# 

__dff_module_regedit_version__ = "1.0.0"

from PyQt4 import QtCore, QtGui
from PyQt4.QtCore import Qt, SIGNAL, QByteArray
from PyQt4.QtGui import QWidget, QVBoxLayout, QDialog

from dff.api.vfs.vfs import vfs
from dff.api.module.module import Module
from dff.api.module.script import Script
from dff.api.types.libtypes import Variant, VList, VMap, Argument, Parameter, typeId
from dff.modules.viewer.pdf.pdfWidget import PDFViewer

import popplerqt4

class PDF(QWidget, Script):
  def __init__(self):
    Script.__init__(self, "PDF viewer")
    self.name = "PDF viewer"
    self.vfs = vfs()
    self.icon = None
  
  def start(self, args):
#    self.args = args
    self.node = args["file"].value()
    try:
      self.preview = args["preview"].value()
    except IndexError:
      self.preview = False
      print "Preview error"
      return

  def g_display(self):
    QWidget.__init__(self, None)
    vlayout = QVBoxLayout()
    self.pdfviewer = PDFViewer(self, self.node)
    vlayout.addWidget(self.pdfviewer)
    self.setLayout(vlayout)

  def updateWidget(self):
	pass

class pdf(Module):
  """PDF file format viewer"""
  def __init__(self):
    Module.__init__(self, "PDF viewer", PDF)
    self.conf.addArgument({"input": Argument.Required|Argument.Single|typeId.Node,
                           "name": "file",
                           "description": "File to display as PDF"})
    self.conf.addArgument({"name": "preview",
			   "description": "Preview mode",
			   "input": Argument.Empty})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["PDF"]})
    self.tags = "Viewers"
    self.flags = ["gui"]
    self.icon = ":pdf"
