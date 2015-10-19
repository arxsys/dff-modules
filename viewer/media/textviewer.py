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
#  Jeremy MOUNIER <jmo@digital-forensic.org>

__dff_module_cat_version__ = "1.0.0"

from PyQt4.QtCore import Qt, QString, SIGNAL, QTextCodec, QPropertyAnimation, QRect, QEasingCurve
from PyQt4.QtGui import QWidget, QTextCursor, QTextEdit, QTextOption, QScrollBar, QAbstractSlider, QHBoxLayout, QListWidget, QVBoxLayout, QSplitter, QSizePolicy, QMessageBox, QPushButton, QShortcut, QKeySequence, QLineEdit, QSizePolicy

from dff.api.vfs import vfs 
from dff.api.types.libtypes import Argument, typeId
from dff.api.module.module import Module 
from dff.api.module.script import Script


class FindBar(QWidget):
  def __init__(self, parent):
    QWidget.__init__(self, parent)
    self.query = QLineEdit(self)
    self.query.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
    self.connect(self.query, SIGNAL("textChanged(const QString &)"), self.queryChanged)
    self.previous = QPushButton("^", self)
    self.previous.setMaximumSize(20, 30)
    self.previous.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
    self.connect(self.previous, SIGNAL("clicked()"), self.previousClicked)
    self.next = QPushButton("v", self)
    self.next.setMaximumSize(20, 30)
    self.next.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
    self.connect(self.previous, SIGNAL("clicked()"), self.nextClicked)
    self.close = QPushButton("x", self)
    self.close.setMaximumSize(20, 30)
    self.close.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)
    self.connect(self.close, SIGNAL("clicked()"), self.hideBar)
    hbox = QHBoxLayout(self)
    hbox.setSpacing(0)
    hbox.addWidget(self.query)
    hbox.addWidget(self.previous)
    hbox.addWidget(self.next)
    hbox.addWidget(self.close)


  def hideBar(self):
    self.setGeometry(0, 0, 0, 0)


  def previousClicked(self):
    self.emit(SIGNAL("previous"))


  def nextClicked(self):
    self.emit(SIGNAL("next"))


  def queryChanged(self):
    self.emit(SIGNAL("queryChanged"), self.query.text())


class CAT(QSplitter, Script):
  def __init__(self):
    Script.__init__(self, "cat")
    self.vfs = vfs.vfs()
    self.type = "cat"
    self.icon = None
    self.currentCodec = "UTF-8"
 

  def start(self, args):
    self.args = args
    try :
      self.preview = args["preview"].value()
    except IndexError:
      self.preview = False
    try:
      self.node = args["file"].value()
    except:
      pass


  def g_display(self):
    QSplitter.__init__(self)
    process = False
    self.initShape()
    if self.node.size() > 30*(1024**2):
      if self.preview:
        self.renderButton.show()
        self.text.setText("The document you are trying to read is greater than 30MiB.\nIt will consume memory and take some time to process.\nif you really want to open it, click on Render button.")
      else:
        warn = "The document you are trying to read is greater than 30MiB.\nIt will consume memory and take some time to process.\nAre you sure you want to open it?"
        ret = QMessageBox.warning(self, self.tr("Text reader"), self.tr(warn), QMessageBox.Yes|QMessageBox.No)
        if ret == QMessageBox.Yes:
          process = True
    else:
      process = True
    if process:
      self.render()


  def initShape(self):
    self.listWidget = QListWidget()
    self.listWidget.setSortingEnabled(True)
    for codec in QTextCodec.availableCodecs():
	 self.listWidget.addItem(str(codec))
    item = self.listWidget.findItems('UTF-8', Qt.MatchExactly)[0]
    self.listWidget.setCurrentItem(item)
    self.listWidget.scrollToItem(item)
    self.connect(self.listWidget, SIGNAL("itemSelectionChanged()"), self.codecChanged)

    self.renderButton = QPushButton("Render", self)
    self.renderButton.hide()
    self.connect(self.renderButton, SIGNAL("clicked()"), self.forceRendering)

    vbox = QVBoxLayout()
    vbox.addWidget(self.listWidget)
    vbox.addWidget(self.renderButton)
    lwidget = QWidget(self)
    lwidget.setLayout(vbox)

    self.text = QTextEdit(self)
    self.text.setReadOnly(1)
    self.text.setWordWrapMode(QTextOption.NoWrap)


    self.findBar = FindBar(self.text)
    shortcut = QShortcut(QKeySequence(self.tr("Ctrl+f", "Search")), self)
    self.findBar.setGeometry(0, 0, 0, 0)
    self.connect(shortcut, SIGNAL("activated()"), self.toggleSearch)
    self.connect(self.findBar, SIGNAL("queryChanged"), self.search)
    #self.searchButton.hide()
    
    self.addWidget(lwidget)
    self.addWidget(self.text)
    #self.addWidget(self.searchButton)
    self.setStretchFactor(0, 0)  
    self.setStretchFactor(1, 1)  
 

  def search(self, text):
    print "Looking for", text


  def codecChanged(self):
     self.currentCodec = self.listWidget.selectedItems()[0].text()
     self.render()


  def forceRendering(self):
    self.renderButton.hide()
    self.render()


  def toggleSearch(self):
    self.showAnimation = QPropertyAnimation(self.findBar, "geometry")
    self.showAnimation.setDuration(200)
    parentGeometry = self.text.geometry()
    startGeometry = QRect(parentGeometry.width() - 300, 0, 300, 0)
    endGeometry = QRect(parentGeometry.width() - 300, 0, 300, 40)
    self.showAnimation.setStartValue(startGeometry)
    self.showAnimation.setEndValue(endGeometry)
    self.showAnimation.start()
    

  def render(self):
    try:
      vfile = self.node.open()
      buff = vfile.read()
      vfile.close()
    except:
      QMessageBox.critical(self, self.tr("Text reader"), 
                           self.tr("Cannot open or read the content of ") + self.node.absolute(),  
                           QMessageBox.Ok)
      return
    codec = QTextCodec.codecForName(self.currentCodec)
    decoder = codec.makeDecoder()
    unicodeText = decoder.toUnicode(buff)
    self.text.clear()
    self.text.textCursor().insertText(unicodeText)
    self.text.moveCursor(QTextCursor.Start)


  def updateWidget(self):
	pass


  def c_display(self):
    file = self.node.open()
    fsize = self.node.size()
    size = 0
    self.buff = ""
    while size < fsize:
      try:
       tmp = file.read(4096)
      except vfsError, e:
        print self.buff
        break
      if len(tmp) == 0:
        print tmp
        break         
      size += len(tmp)
      self.buff += tmp
      print tmp
    file.close()
    if len(self.buff): 
     return self.buff


class textviewer(Module):
  """Displays content of files as text
ex:cat /myfile.txt"""
  def __init__(self):
    Module.__init__(self, "textviewer", CAT)
    self.conf.addArgument({"name": "file",
                           "description": "Text file to display",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addArgument({"name": "preview",
			   "description": "Preview mode",
			   "input": Argument.Empty})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["HTML", "ASCII", "XML", "text"]})
    self.tags = "Viewers"
    self.flags = ["console", "gui"]
    self.icon = ":text"	
