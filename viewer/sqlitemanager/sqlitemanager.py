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

__dff_module_sqlitemanager_version__ = "1.0.0"

from PyQt4.QtCore import Qt, QString, SIGNAL
from PyQt4.QtGui import QWidget, QVBoxLayout

#from dff.api.vfs import vfs
from dff.api.types.libtypes import Argument, typeId
from dff.api.module.module import Module 
from dff.api.module.script import Script

from dff.modules.viewer.sqlitemanager.manager import Manager

from dff.modules.viewer.sqlitemanager.manager import Manager

class SQLITEMANAGER(QWidget, Script):
  def __init__(self):
    Script.__init__(self, "sqlitemanager")
#    self.vfs = vfs.vfs()
    self.type = "sqlite"
    self.icon = None

  def start(self, args):
    self.args = args
    print args
    # try:
    #   self.node = args["file"].value()
    # except:
    #   pass

  def g_display(self):
    QWidget.__init__(self)
    self.vlayout = QVBoxLayout()
    self.manager = Manager()
    self.vlayout.addWidget(self.manager)
    self.setLayout(self.vlayout)

  def updateWidget(self):
    pass

  def c_display(self):
    print "Not supported"

class sqlitemanager(Module):
  """graphical SQLite database manager"""
  def __init__(self):
    Module.__init__(self, "sqlitemanager", SQLITEMANAGER)
    self.tags = "Viewers"
    self.flags = ["gui"]
    self.icon = ":database"	
