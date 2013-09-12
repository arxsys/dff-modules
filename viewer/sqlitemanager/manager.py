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

from PyQt4.QtCore import QVariant, SIGNAL, QThread, Qt, QFile, QIODevice, QStringList, QRect, SLOT, QEvent, QString, QSignalMapper, pyqtSignal, pyqtSlot, SLOT
from PyQt4.QtGui import QWidget, QTreeWidgetItem, QIcon, QTableWidgetItem, QColor, QTableWidget, QAbstractItemView, QHeaderView, QMenu, QFileDialog

from dff.api.module.manager import ModuleProcessusManager
from dff.api.vfs.vfs import vfs
from dff.api.filters.libfilters import Filter
from dff.api.events.libevents import EventHandler

import apsw

import time
from datetime import *

from dff.ui.gui.resources.ui_sqlitemanager import Ui_SQLiteManager

TABINDEX = ['BROWSE', 'CUSTOM', 'SCHEMA']
 
class Manager(Ui_SQLiteManager, QWidget, EventHandler):
    def __init__(self):
        QWidget.__init__(self)
        self.setupUi(self)
        self.databases = []
        self.proc = ModuleProcessusManager().get('SqliteDB')
        self.createTables()

        self.connect(self.databaseTree, SIGNAL("itemClicked(QTreeWidgetItem*,int)"), self.selectTable)
        self.connect(self.queryRun, SIGNAL("clicked()"), self.runQuery)
        self.connect(self.selectDatabase, SIGNAL("currentIndexChanged(int )"), self.customDatabaseChanged)
        self.connect(self.tableResult, SIGNAL("itemClicked(QTableWidgetItem*)"), self.tableClicked)
        self.connect(self.queryResult, SIGNAL("itemClicked(QTableWidgetItem*)"), self.tableClicked)
        # Actions
        self.connect(self.actionExport_selection_CSV, SIGNAL("triggered(bool)"), self.exportCSV)
        self.connect(self.actionExtract_Binary_BLOB, SIGNAL("triggered(bool)"), self.exportBLOB)
        self.connect(self.actionDecode_date_column, SIGNAL("triggered(bool)"), self.decodeDate)
        self.connect(self.actionReset_column, SIGNAL("triggered(bool)"), self.resetColumn)

        self.searchForDatabases()
        self.currentDB = None
        self.queryMessage.setTextColor(Qt.red)


    def resetColumn(self):
        table = self.currentTable()
        item = table.currentItem()
        if item:
            column = item.column()
            for row in xrange(0, table.rowCount()):
                table.item(row, column).format()

    def decodeDate(self):
        table = self.currentTable()
        item = table.currentItem()
        if item:
            column = item.column()
            for row in xrange(0, table.rowCount()):
                i = table.item(row, column)
                ts = i.getData()
                if ts:
                    dt = datetime.fromtimestamp(ts/1000000)
                    i.setText(QString(dt.isoformat()))

    def exportCSV(self, state):
        # Get current table
        table = self.currentTable()
        columns = table.columnCount()
        csv = QString("")
        header = table.horizontalHeader()
        # Build CSV header
        for colid in xrange(0, columns):
            csv.append(table.horizontalHeaderItem(colid).text())
            csv.append(",")
        csv.append("\n")
        # Get selected Rows (id)
        selectedRows = self.selectedRows(table)
        # Build csv
        for row in selectedRows:
            for col in xrange(0, table.columnCount()):
                item = table.item(row, col)
                csv.append(item.text())
                csv.append(",")
            csv.append("\n")
        # Write to file
        sFileName = QFileDialog.getSaveFileName(self, "Export CSV", "sqlite.csv")
        if sFileName:
            with open(sFileName, "w") as f:
                f.write(csv)        

    def selectedRows(self, table):
        selectedRows = []
        for row in xrange(0, table.rowCount()):
            if table.item(row, 0).isSelected():
                selectedRows.append(row)
        return selectedRows

    def currentTable(self):
        if TABINDEX[self.tabWidget.currentIndex()] is "CUSTOM":
            return self.queryResult
        else:
            return self.tableResult

    def exportBLOB(self, state):
        table = self.currentTable()
        data = table.currentItem().getData()
        sFileName = QFileDialog.getSaveFileName(self, "Export Binary content", "Specify")
        if sFileName:
            with open(sFileName, "w") as f:
                f.write(data)

    def createTables(self):
        self.queryResult = TableResult(self, custom=True)
        self.tableResult = TableResult(self)

        self.customResultLayout.addWidget(self.queryResult)
        self.tableResultLayout.addWidget(self.tableResult)

    def tableClicked(self, item):
        table = item.tableWidget()

    def customDatabaseChanged(self, index):
        self.setCurrentDatabase(self.databases[index])

    def runQuery(self):
        self.customStack.setCurrentIndex(0)
        query = self.queryEdit.toPlainText()
        if self.currentDB:
            self.buildDatabaseTable(self.queryResult, query, self.currentDB)

    def headerList(self, cursor):
        heads = []
        if cursor:
            try:
                description = cursor.getdescription()
            except:
                return heads
            for head in description:
                heads.append(head[0])
        return heads

    def currentDatabase(self):
        item = self.databaseTree.currentItem()

    def buildDatabaseTable(self, table, query, database):
        table.setRowCount(0)
        try:
            cursor = self.proc.executeFrom(database, query)
        except apsw.SQLError, e:
            if TABINDEX[self.tabWidget.currentIndex()] is "CUSTOM":
                self.queryMessage.clear()
                self.queryMessage.insertPlainText(QString(str(unicode(e).encode('utf-8'))))
                self.customStack.setCurrentIndex(1)
            return
        heads = self.headerList(cursor)
        table.setColumnCount(len(heads))
        table.setHorizontalHeaderLabels(heads)
        # Align header title
        for count, head in enumerate(heads):
            table.horizontalHeaderItem(count).setTextAlignment(Qt.AlignLeft)
        for row, c in enumerate(cursor):
            for count, data in enumerate(c):
                table.setRowCount(row + 1)
                table.setItem(row, count, DatabaseTableItem(data))

    def setCurrentDatabase(self, db):
        self.currentDB = db
        self.selectDatabase.setCurrentIndex(self.databases.index(db))

    def selectTable(self, item, col):
        if item.isTable():
            self.setCurrentDatabase(item.nodeDB())
            query = "SELECT * FROM " + item.text(0)
            self.buildDatabaseTable(self.tableResult, query, item.nodeDB())
            qschema = "pragma table_info('" + item.text(0) + "')"
            self.populateSchema(item.nodeDB(), qschema)

    def populateSchema(self, db, query):
        self.schemaTable.setRowCount(0)
        try:
            rows = self.proc.executeFrom(db, query).fetchall()
        except apsw.SQLError, e:
            return
        for rcount, row in enumerate(rows):
            for ccount, col in enumerate(row):
                self.schemaTable.setRowCount(rcount + 1)
                self.schemaTable.setItem(rcount, ccount, DatabaseTableItem(col))

    def populateTree(self):
        for db in self.databases:
            item = DatabaseTreeItem(self.databaseTree, db)
            item.setText(0, QString.fromUtf8(db.name()))
            item.setIcon(0, QIcon(":database"))
            cursor = self.proc.executeFrom(db, 'SELECT tbl_name FROM sqlite_master where type="table";')
            for c in cursor:
                tableitem = DatabaseTreeItem(item, db, isTable=True)
                tableitem.setText(0, QString.fromUtf8(c[0]))


    def searchForDatabases(self):
        if len(self.proc.databases):
            for base, node in self.proc.databases.iteritems():
                self.databases.append(node)
                self.selectDatabase.addItem(QString.fromUtf8(node.name()))
            self.populateTree()


class DatabaseTableItem(QTableWidgetItem):
    def __init__(self, data):
        QTableWidgetItem.__init__(self)
        self.__data = data
        self.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)
        self.__type = None
        self.format()

    def getType(self):
        return self.__type

    def format(self):
        self.__type = t = type(self.__data).__name__
        if t == "int":
            self.setText(QString(str(self.__data)))
            self.setBackgroundColor(QColor(204, 255, 204))
            return str(self.__data)
        elif t == "unicode":
            self.setText(QString.fromUtf8(self.__data))
            self.setBackgroundColor(QColor(204, 255, 255))
            return self.__data
        elif t == "long":
            self.setText(QString.fromUtf8(str(self.__data)))
            self.setBackgroundColor(QColor(204, 255, 204))
            return str(self.__data)
        elif t == "buffer":
            self.setText(QString("BLOB (Size: " + str(len(self.__data)) + ")"))
            self.setBackgroundColor(QColor(204, 204, 255))
            return "BLOB (Size: " + str(len(self.__data))
        elif t == "NoneType":
            self.setText(QString(""))
            self.setBackgroundColor(QColor(255, 204, 204))
            return ""
        else:
            return None

    def getData(self):
        return self.__data

class DatabaseTreeItem(QTreeWidgetItem):
    def __init__(self, parent, nodeDB, isTable=False):
        QTreeWidgetItem.__init__(self, parent)
        self.__isTable = isTable
        self.__nodeDB = nodeDB
        self.setFlags(Qt.ItemIsSelectable|Qt.ItemIsEnabled)

    def nodeDB(self):
        return self.__nodeDB

    def isTable(self):
        return self.__isTable

class TableResult(QTableWidget):
    def __init__(self, parent, custom=False):
        QTableWidget.__init__(self, parent)
        self.manager = parent
        self.custom = custom
        self.config()
        self.__selectedItem = None

    def config(self):
        # Horizontal Header configuration
        header = QHeaderView(Qt.Horizontal)
        header.setVisible(True)
        self.setHorizontalHeader(header)
        # Vertical Header configuration
        vheader = QHeaderView(Qt.Vertical)
        vheader.setVisible(False)
        vheader.setDefaultSectionSize(20)
        vheader.setMinimumSectionSize(20)
        self.setVerticalHeader(vheader)
        # Table Configuration
        self.setHorizontalScrollMode(QAbstractItemView.ScrollPerPixel)
        self.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.setTextElideMode(Qt.ElideRight)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)

    def currentItem(self):
        return self.__selectedItem

    def mousePressEvent(self, event):
        item = self.itemAt(event.pos())
        if item != None:
            self.__selectedItem = item
            if event.button() == Qt.RightButton:
                self.buildMenu(event)
        return QAbstractItemView.mousePressEvent(self, event)

    def buildMenu(self, event):
        item = self.itemAt(event.pos())
        menu = QMenu(self)
        menu.addAction(self.manager.actionExport_selection_CSV)
        if item.getType() == "buffer":
            menu.addAction(self.manager.actionExtract_Binary_BLOB)
        menu.addAction(self.manager.actionDecode_date_column)
        menu.addAction(self.manager.actionReset_column)
        menu.popup(event.globalPos())


# class SearchDatabase(QThread, EventHandler):
#     def __init__(self):
#         EventHandler.__init__(self)
#         QThread.__init__(self)
#         self.vfs = vfs()
#         self.root = self.vfs.getnode("/")
#         self.__filter = Filter("sqlite")
#         self.__filter.connection(self)
#         self.init()

#     def init(self):
#         self.__nodesToProcess = 0
#         self.__processedNodes = 0
#         self.percent = 0

#     def run(self):
#         self.searchProcess()

#     def searchProcess(self):
#         self.__filter.compile('magic matches "SQLite"')
#         self.__filter.process(self.root, True)
        
#     def Event(self, ev):
#         try:
#             if not ev:
#                 return
#             if ev.type == Filter.TotalNodesToProcess:
#                 self.__nodesToProcess = ev.value.value()
#             elif ev.type == Filter.ProcessedNodes:
#                 if not (ev.value.value() > self.__nodesToProcess):
#                     self.__processedNodes += 1
#             elif ev.type == Filter.NodeMatched:
#                 pass
#             elif ev.type == Filter.EndOfProcessing:
#                 bases = self.__filter.matchedNodes()
#                 self.emit(SIGNAL("searchDone"), bases) 
#             pc = self.__processedNodes * 100 / self.__nodesToProcess
#             try:
#                 if pc > self.percent:
#                     self.percent = pc
#                     self.emit(SIGNAL("searchCount"), self.percent)
#             except:
#                 self.percent = 0
#         except:
#             print "Unknown Exception"
