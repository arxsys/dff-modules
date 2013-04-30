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

from PyQt4.QtCore import SIGNAL, Qt, QFile, SLOT, QEvent, QString
from PyQt4.QtGui import QWidget, QGraphicsScene, QGraphicsView, QVBoxLayout, QPixmap

from dff.ui.gui.resources.ui_pdf_toolbar import Ui_pdfToolbar

import popplerqt4

#XXX todo : Enter password popup if protected ( Latin1-encoded )

class PDFViewer(QWidget, Ui_pdfToolbar):
    def __init__(self, parent):
        super(QWidget, self).__init__(parent)
        self.setupUi(self)
        self.shape()
        self.setDocumentInformation(parent.node)
        self.setScripts()
        self.buildPage(1)
        self.setMetadata()

    def shape(self):
        self.connect(self.selectPage, SIGNAL("valueChanged(int)"), self.changePage)
        self.connect(self.scaleBox, SIGNAL("currentIndexChanged (int)"), self.scale)
        self.connect(self.nextButton, SIGNAL("clicked(bool)"), self.nextPage)
        self.connect(self.previousButton, SIGNAL("clicked(bool)"), self.previousPage)
        self.metadataEdit.setReadOnly(True)
        self.annotationsEdit.setReadOnly(True)
        self.scene = QGraphicsScene()
        self.view = QGraphicsView(self.scene)
        self.pdfscene.addWidget(self.view)
        self.previousButton.setEnabled(False)

    def setMetadata(self):
        self.metadataEdit.insertPlainText(self.document.metadata())

    def setAnnotations(self):
        pageID = self.selectPage.value()
        pid = (0 if pageID is 1 else pageID - 1)
        page = self.document.page(pid)
        annotations = page.annotations()
        self.annotationsEdit.clear()
        for count, annotation in enumerate(annotations):
            self.annotationsEdit.insertPlainText(QString(annotation.contents()))
            self.annotationsEdit.insertPlainText(QString("\n"))

    def setScripts(self):
        scripts = self.document.scripts()
        if len(scripts) > 0:
            for count, script in enumerate(scripts):
                scriptedit = QTextEdit(QString(script))
                scriptedit.setReadOnly(True)
                self.scriptsTab.addTab(scriptEdit, str(count))
        else:
            self.tabWidget.setTabEnabled(1, False)

    def enabledButtons(self):
        self.previousButton.setEnabled((self.selectPage.value() > self.selectPage.minimum()))
        self.nextButton.setEnabled((self.selectPage.value() < self.selectPage.maximum()))
        
    def nextPage(self):
        pageid = (self.selectPage.maximum() if self.selectPage.value() == self.selectPage.maximum() else self.selectPage.value() + 1)
        self.selectPage.setValue(pageid)

    def previousPage(self):
        pageid = (self.selectPage.minimum() if self.selectPage.value() == self.selectPage.minimum() else self.selectPage.value() - 1)
        self.selectPage.setValue(pageid)

    def changePage(self, pageID):
        self.scale(self.scaleBox.currentIndex())
        self.enabledButtons()

    # def searchPattern(self):
    #     pattern =  self.searchEdit.text()
    #     page = self.document.page(self.selectPage.value())
    #     print page.search(pattern)

    def scale(self, index):
        self.buildPage(self.selectPage.value())

    def setDocumentInformation(self, node):
        self.__node = node
        try:
            vfile = node.open()
            buff = vfile.read()
            vfile.close()
            self.document = popplerqt4.Poppler.Document.loadFromData(buff)
            self.selectPage.setMinimum(1)
            self.selectPage.setMaximum(self.document.numPages())
            self.totalPages.clear()
            self.totalPages.setText(str(self.document.numPages()))
        except:
            return

    def buildPage(self, pageID):
        pid = (0 if pageID is 1 else pageID - 1)
        self.scene.clear()
        res = int(self.scaleBox.currentText())
        page = self.document.page(pid)
        image = page.renderToImage(res, res)
        pixmap = QPixmap(QPixmap.fromImage(image))
        self.scene.addPixmap(pixmap)
        self.setAnnotations()
        # Extract all text from page
        # tlist = page.textList()
        # for text in tlist:
        #     # unicode 
        #     print QString.fromUtf8(text.text())
