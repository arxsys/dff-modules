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
from PyQt4.QtGui import QWidget, QGraphicsScene, QGraphicsView, QVBoxLayout, QPixmap, QTextEdit
from dff.ui.gui.resources.ui_pdf_toolbar import Ui_pdfToolbar

import popplerqt4


class PDFView(QGraphicsView):
    def __init__(self, parent, scene):
        super(QGraphicsView, self).__init__(scene)
        self.viewer = parent

    def wheelEvent(self, wEvent):
        scrollbar = self.verticalScrollBar()
        if (scrollbar.value() >= scrollbar.maximum()) and (wEvent.delta() < 0):
            self.viewer.nextPage()
            scrollbar.setValue(scrollbar.minimum())
        elif (scrollbar.value() <= 0) and (wEvent.delta() > 0):
            self.viewer.previousPage()
            scrollbar.setValue(scrollbar.maximum())
        else:
            if wEvent.delta() > 0:
                scrollbar.setValue(scrollbar.value() - scrollbar.pageStep())
            else:
                scrollbar.setValue(scrollbar.value() + scrollbar.pageStep())


class PDFViewer(QWidget, Ui_pdfToolbar):
    def __init__(self, parent, node):
        super(QWidget, self).__init__(parent)
        self.setupUi(self)
        self.node = node
        self.shape()
        self.setDocumentInformation()

    def shape(self):
        self.metadataEdit.setReadOnly(True)
        self.annotationsEdit.setReadOnly(True)
        self.scene = QGraphicsScene()
        self.view = PDFView(self, self.scene)
        self.pdfscene.addWidget(self.view)
        self.previousButton.setEnabled(False)

        self.connect(self.selectPage, SIGNAL("valueChanged(int)"), self.changePage)
        self.connect(self.scaleBox, SIGNAL("currentIndexChanged (int)"), self.scale)
        self.connect(self.nextButton, SIGNAL("clicked(bool)"), self.nextPage)
        self.connect(self.previousButton, SIGNAL("clicked(bool)"), self.previousPage)
        self.connect(self.unlockButton, SIGNAL("clicked(bool)"), self.unlockDocument)

    def unlockDocument(self):
        ownerpwd = self.owneredit.text().toLatin1()
        userpwd = self.useredit.text().toLatin1()
        self.setDocumentInformation(ownerpwd, userpwd)
        self.stack.setCurrentIndex(0)

    def setMetadata(self):
        if self.document.metadata() != "":
            self.metadataEdit.insertPlainText(self.document.metadata())
        else:
            self.tabWidget.setTabEnabled(2, False)

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
                self.scriptsTab.addTab(scriptedit, str(count))
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

    def scale(self, index):
        self.buildPage(self.selectPage.value())

    def setDocumentInformation(self, ownerpwd=None, userpwd=None):
        try:
            vfile = self.node.open()
            buff = vfile.read()
            vfile.close()
        except:
            return None
        if not ownerpwd:
            document = popplerqt4.Poppler.Document.loadFromData(buff)
        else:
            document = popplerqt4.Poppler.Document.loadFromData(buff, ownerpwd, userpwd)
        if document.isLocked():
            self.nextButton.setEnabled(False)
            self.previousButton.setEnabled(False)
            self.stack.setCurrentIndex(1)
            return False
        else:
            self.enabledButtons()
            self.document = document
            self.selectPage.setMinimum(1)
            self.selectPage.setMaximum(self.document.numPages())
            self.totalPages.clear()
            self.totalPages.setText(str(self.document.numPages()))
            self.setScripts()
            self.buildPage(1)
            self.setMetadata()
            return True

    def buildPage(self, pageID):
        pid = (0 if pageID is 1 else pageID - 1)
        self.scene.clear()
        res = int(self.scaleBox.currentText())
        page = self.document.page(pid)
        image = page.renderToImage(res, res)
        pixmap = QPixmap(QPixmap.fromImage(image))
        self.scene.addPixmap(pixmap)
        self.setAnnotations()
        self.scene.update()
