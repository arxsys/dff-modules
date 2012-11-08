# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2011 ArxSys
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
# 

__dff_module_extract_version__ = "1.0.0"

import os
import time
import traceback
import types
import shutil

from dff.api.vfs import *
from dff.api.vfs.extract import Extract
from dff.api.module.script import *
from dff.api.events.libevents import EventHandler
from dff.api.exceptions.libexceptions import *
from dff.api.types.libtypes import Argument, typeId, Variant
from dff.api.module.module import *

# Extract algorithm
#  Examples are based on the following tree:
#  /
#  |- foo
#      |- bar
#          |- tutu
#          |- toto
#          |- tata
#
#  and extraction folder is /home/user/extract
#  
#  Preserve tree example while extracting from /foo/bar/tutu
#  if enabled:
#     tutu will be extracted as follow: /home/user/extract/foo/bar/tutu
#  if disabled
#     tutu will be extracted as follow: /home/user/extract/tutu
#
#  Recursive example while extracting from /foo
#  if enabled:
#     if bar is both a file and a folder (after applying a module on it)
#        /home/user/extract/bar.bin
#        /home/user/extract/bar/{tutu,toto,tata}
#     else
#        /home/user/extract/bar/{tutu,toto,tata}
#  if disabled:
#     either bar is both a file and a folder or a single file
#        /home/user/extract/bar (extracted as a file)
#
#  File System destination folder handling
#  Since 
#
#


class EXTRACT(Script, EventHandler):
  reservednames = ['CON', 'PRN', 'AUX', 'CLOCK$', 'NUL',
                 'COM0', 'COM1', 'COM2', 'COM3', 'COM4', 'COM5', 'COM6', 'COM7', 'COM8', 'COM9',
                 'LPT0', 'LPT1', 'LPT2', 'LPT3', 'LPT4', 'LPT5', 'LPT6', 'LPT7', 'LPT8', 'LPT9',
                 '$AttrDef', '$BadClus', '$Bitmap', '$Boot', '$LogFile', '$MFT', '$MFTMirr', 
                 'pagefile.sys', '$Secure', '$UpCase', '$Volume', '$Extend']

  max_depth = 2**31-1

  def __init__(self):
    Script.__init__(self, "extract")
    EventHandler.__init__(self)
    self.vfs = vfs.vfs()
    self.extractor = Extract()
    self.extractor.connection(self)


  def start(self, args):
    self.total_files = 0
    self.total_folders = 0
    self.extracted_files = 0
    self.extracted_folders = 0
    self.files_errors = 0
    self.folders_errors = 0
    self.ommited_files = 0
    self.ommited_folders = 0
    self.log = {"files": {"ok": "", "nok": ""},
                "folders": {"ok": "", "nok": ""}}
    try:
      self.nodes = args['files'].value()
      self.syspath = args['syspath'].value().path
      if not os.path.isdir(self.syspath):
        self.res["errors"] = Variant(self.syspath + " is not a valid directory")
        return
      if args.has_key('recursive'):
        self.recursive = args["recursive"].value()
      else:
        self.recursive = False
      if args.has_key('preserve'):
        self.preserve = args["preserve"].value()
      else:
        self.preserve = False
      if args.has_key('overwrite'):
        self.overwrite = args["overwrite"].value()
      else:
        self.overwrite = False
      self.__extract()
    except KeyError:
      pass


  def Event(self, e):
    if e.type == Extract.FileProgress:
      idx = self.stateinfo.rfind("extracting")
      vl = e.value.value()
      node = vl[0].value()
      percent = vl[1].value()
      if idx != -1:
        buff = self.stateinfo[:idx]
        buff += "extracting " + node.absolute() + ": " + str(percent) + " %"
        self.stateinfo = buff
      else:
        self.stateinfo += "extracting " + node.absolute() + ": " + str(percent) + " %"
    if e.type == Extract.OverallProgress:
      self.stateinfo = str(e.value)
    if e.type == Extract.FileFailed:
      vl = e.value.value()
      print "extracting file failed", vl[0].value(), "\n", vl[1]
    if e.type == Extract.FolderFailed:
      vl = e.value.value()
      print "extracting folder failed", vl[0].value(), "\n", vl[1]


  def __extract(self):
    for vnode in self.nodes:
      node = vnode.value()
      if self.recursive:
        self.extractor.extractTree(node, self.syspath, self.preserve, self.overwrite)
      else:
        if node.hasChildren() or node.isDir():
          self.extractor.extractFolder(node, self.syspath, self.preserve, self.overwrite)
        else:
          self.extractor.extractFile(node, self.syspath, self.preserve, self.overwrite)


  def createReport(self):
    stats = ""
    if self.total_files > 0:
      percent = (float(self.extracted_files) * 100) / self.total_files
      stats += "extracted file(s):   " + str(self.extracted_files) + "/" + str(self.total_files) + " (" + str(round(percent, 2)) + "%)\n"

    if self.total_folders > 0:
      percent = (float(self.extracted_folders) * 100) / self.total_folders
      stats += "extracted folder(s): " + str(self.extracted_folders) + "/" + str(self.total_folders) + " (" + str(round(percent, 2)) + "%)\n" 

    if self.ommited_files > 0:
      percent = (float(self.ommited_files) * 100) / self.total_files
      stats += "ommited file(s):     " + str(self.ommited_files) + "/" + str(self.total_files) + " (" + str(round(percent, 2)) + "%)\n"

    if self.ommited_folders > 0:
      percent = (float(self.ommited_folders) * 100) / self.total_folders
      stats += "ommited folder(s):   " + str(self.ommited_folders) + "/" + str(self.total_folders) + " (" + str(round(percent, 2)) + "%)\n"

    if self.files_errors > 0:
      percent = (float(self.files_errors) * 100) / self.total_files
      stats += "file(s) error:       " + str(self.files_errors) + "/" + str(self.total_files) + " (" + str(round(percent, 2)) + "%)\n"
      self.res["file(s) errors"] = Variant(self.log["files"]["nok"])


    if self.folders_errors > 0:
      percent = (float(self.folders_errors) * 100) / self.total_folders
      stats += "folder(s) error:     " + str(self.folders_errors) + "/" + str(self.total_folders) + " (" + str(round(percent, 2)) + "%)\n"
      self.res["folder(s) errors"] = Variant(self.log["folders"]["nok"])

    if len(stats):
      self.res["statistics"] = Variant(stats)


class extract(Module):
  """Extract file in your operating system file system."""
  def __init__(self):
    Module.__init__(self, "extract", EXTRACT)
    self.conf.addArgument({"name": "files",
                           "description": "Files or directories list to extract",
                           "input": Argument.Required|Argument.List|typeId.Node})
    self.conf.addArgument({"name": "syspath",
                           "description": "Local file system path where files will be extracted",
                           "input": Argument.Required|Argument.Single|typeId.Path})
    self.conf.addArgument({"name": "recursive",
                           "description": "Extract recursivly each files in all sub-directories",
                           "input": Argument.Empty})
    self.conf.addArgument({"name": "preserve",
                           "description": "Enables if the absolute path needs to be preserved",
                           "input": Argument.Empty})
    self.conf.addArgument({"name": "overwrite",
                           "description": "Enables if already existing files in extraction folder exist",
                           "input": Argument.Empty})
    #self.conf.addArgument({"name": "ascii_only",
    #                       "description": "Enables if destination folder's filesystem only supports ascii filenames",
    #                       "input": Argument.Empty})
    self.tags = "Export"
    self.icon = ":extract.png"
