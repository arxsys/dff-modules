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
#  Samuel CHEVET <gw4kfu@gmail.com>
#  Frederic Baguelin <fba@digital-forensic.org>
#

__dff_module_volatility_version__ = "1.0.0"

VOLATILITY_PATH = "/home/udgover/sources/volatility-2.2"
#VOLATILITY_PATH = "/home/udgover/sources/volatility-"

import sys
import os
import traceback


from dff.api.module.module import Module
from dff.api.vfs.libvfs import mfso, AttributesHandler, Node
from dff.api.types.libtypes import Variant, VMap, VList, typeId, Argument, Parameter, vtime, TIME_MS_64

if VOLATILITY_PATH:
   sys.path.append(VOLATILITY_PATH)
try:
   from dff.modules.ram.addrspace import dffvol
   import volatility.conf as conf
   import volatility.timefmt as timefmt
   import volatility.constants as constants
   import volatility.registry as registry
   import volatility.exceptions as exceptions
   import volatility.obj as obj
   import volatility.debug as debug
   
   import volatility.utils as utils

   import volatility.plugins.kdbgscan as kdbgscan
   import volatility.plugins.imageinfo as imageinfo

   import volatility.addrspace as addrspace
   import volatility.commands as commands
   import volatility.scan as scan
   
   import volatility.win32.tasks as tasks
   import volatility.plugins.taskmods as taskmods
   import volatility.plugins.handles as handles
   import volatility.plugins.modscan as modscan
   import volatility.plugins.filescan as filescan

   from volatility.plugins.filescan import PoolScanProcess

   import volatility.plugins.taskmods as taskmods
   
   import volatility.registry as registry
   import volatility.win32.network as network
   
   with_volatility = True
except ImportError:
   traceback.print_exc()
   with_volatility = False


from winproc import WinProcNode

import time


class WinRootNode(Node):
   def __init__(self, name, parent, fsobj):
      Node.__init__(self, name, 0, None, fsobj)
      self.__fsobj = fsobj
      self._kdbg = self.__fsobj._kdbg
      self._astype = self.__fsobj._astype
      self.setDir()
      self.__disown__()


   def _attributes(self):
      attribs = VMap()
      kdbg_offsets = VMap()
      proc_head = VMap()
      mod_head = VMap()
      sys_info = VMap()

      sys_info["Chosen profile"] = Variant(self.__fsobj._config.PROFILE)
      sys_info["Major"] = Variant(self._kdbg.obj_vm.profile.metadata.get('major', 0))
      sys_info["Minor"] = Variant(self._kdbg.obj_vm.profile.metadata.get('minor', 0))
      sys_info["Build"] = Variant(self._kdbg.obj_vm.profile.metadata.get('build', 0))
      
      if hasattr(self._kdbg.obj_vm, 'vtop'):
         kdbg_offsets["virtual"] =  Variant(self._kdbg.obj_offset)
         kdbg_offsets["physical"] = Variant(self._kdbg.obj_vm.vtop(self._kdbg.obj_offset))
         sys_info["Service Pack (CmNtCSDVersion)"] = Variant(self._kdbg.ServicePack)
         sys_info["Build string (NtBuildLab)"] = Variant(str(self._kdbg.NtBuildLab.dereference()))
         try:
            num_tasks = len(list(self._kdbg.processes()))
         except AttributeError:
            num_tasks = 0
         try:
            num_modules = len(list(self._kdbg.modules()))
         except AttributeError:
            num_modules = 0
         cpu_blocks = list(self._kdbg.kpcrs())
         
         proc_head["offset"] = Variant(long(self._kdbg.PsActiveProcessHead))
         proc_head["process count"] = Variant(num_tasks)
         mod_head["offset"] = Variant(long(self._kdbg.PsLoadedModuleList))
         mod_head["modules count"] = Variant(num_modules)
         try:
            dos_header = obj.Object("_IMAGE_DOS_HEADER", offset = self._kdbg.KernBase, vm = self._kdbg.obj_vm)
            nt_header = dos_header.get_nt_header()
         except:
            pass
         else:
            sys_info["Major (OptionalHeader)"] = Variant(long(nt_header.OptionalHeader.MajorOperatingSystemVersion))
            sys_info["Minor (OptionalHeader)"] = Variant(long(nt_header.OptionalHeader.MinorOperatingSystemVersion))
         i = 0
         kpcrs = VMap()
         for kpcr in cpu_blocks:
            kpcrs["CPU " + str(kpcr.ProcessorBlock.Number)] = Variant(kpcr.obj_offset)
         attribs["KPCR(s)"] = Variant(kpcrs)
         attribs["DTB"] = Variant(self._astype.dtb)
         volmagic = obj.VolMagic(self._astype)
         KUSER_SHARED_DATA = volmagic.KUSER_SHARED_DATA.v()
         if KUSER_SHARED_DATA:
            attribs["KUSER_SHARED_DATA"] = Variant(KUSER_SHARED_DATA)
            k = obj.Object("_KUSER_SHARED_DATA",
                           offset = KUSER_SHARED_DATA,
                           vm = self._astype)
            if k:
               stime = k.SystemTime
               vtstime = vtime(stime.as_windows_timestamp(), TIME_MS_64)
               vtstime.thisown = False
               attribs["Image date and time"] = Variant(vtstime)
               tz = timefmt.OffsetTzInfo(-k.TimeZoneBias.as_windows_timestamp() / 10000000)
               lsystime = stime.as_datetime().astimezone(tz)
               vtlstime = vtime(lsystime.year, lsystime.month, lsystime.day, lsystime.hour, lsystime.minute, lsystime.second, 0)
               vtlstime.thisown = False
               attribs["Image local date and time"] = Variant(vtlstime)
      else:
         kdbg_offsets["physical"] = Variant(self._kdbg.obj_offset)
         proc_head["offset"] = Variant(self._kdbg.PsActiveProcessHead)
         mod_head["offset"] = Variant(self._kdbg.PsLoadedModuleList)
      attribs["PsActiveProcessHead"] = Variant(proc_head)
      attribs["PsLoadedModuleList"] = Variant(mod_head)
      attribs["KDBG offsets"] = Variant(kdbg_offsets)
      attribs["KernelBase"] = Variant(long(self._kdbg.KernBase))
      if not hasattr(self._astype, "pae"):
         attribs["PAE type"] = Variant("No PAE")
      else:
         attribs["PAE type"] = Variant("PAE")
      verinfo = self._kdbg.dbgkd_version64()
      if verinfo:
         ver64 = VMap()
         ver64["Major"] = Variant(long(verinfo.MajorVersion))
         ver64["Minor"] = Variant(long(verinfo.MinorVersion))
         ver64["offset"] = Variant(verinfo.obj_offset)
         sys_info["Version 64"] = Variant(ver64)
      attribs["System Information"] = Variant(sys_info)
      return attribs



class Volatility(mfso):

   baseconf = {'profile': '', 
               'use_old_as': None, 
               'kdbg': None, 
               'help': False, 
               'kpcr': None, 
               'tz': None, 
               'pid': None, 
               'output_file': None, 
               'physical_offset': None, 
               'conf_file': None, 
               'dtb': None, 
               'output': None, 
               'info': None, 
               'location': None, 
               'plugins': None, 
               'debug': True, 
               'cache_dtb': False, 
               'filename': None, 
               'cache_directory': None, 
               'verbose': None, 
               'write':False}
   
   def __init__(self):
      mfso.__init__(self, "volatility")
      self.__disown__()
      if with_volatility:
         self._config = conf.ConfObject()
         registry.PluginImporter()
         registry.register_global_options(self._config, addrspace.BaseAddressSpace)
         registry.register_global_options(self._config, commands.Command)


   def start(self, args):
      if not with_volatility:
         raise RuntimeError("Volatility not found. Please install it")
      self.memdump = args["file"].value()
      self._config.update('location', "file://" + self.memdump.absolute())
      self._config.update('filename', self.memdump.name())
      self._config.update('debug', True)
      starttime = time.time()
      if args.has_key("profile"):
         self._astype = utils.load_as(self._config, astype='any')
         self._config.update('profile', args['profile'].value())
         self._kdbg = tasks.get_kdbg(self._astype)
         self._config.update('kdbg', self._kdbg.obj_offset)
      else:
         try:
            self.__guessProfile()
         except:
            traceback.print_exc()
      try:
         self.root = WinRootNode("Windows RAM", self.memdump, self)
      except:
         traceback.print_exc()
      

      #for task in taskmods.DllList(self.volconf).calculate():
      #   print task.UniqueProcessId

      #print dir(self.addr_space)
      try:
         self.__createProcessTree()
      except:
         traceback.print_exc()
      self.registerTree(self.memdump, self.root)
      print time.time() - starttime



   def __guessProfile(self):
      bestguess = None
      profiles = [ p.__name__ for p in registry.get_plugin_classes(obj.Profile).values() ]
      scan_kdbg = kdbgscan.KDBGScan(self._config)
      suglist = []
      print "Starting KDBG scan"
      suglist = [ s for s, _ in scan_kdbg.calculate() ]
      print "KDBG scan finished"
      if suglist:
         bestguess = suglist[0]
      if bestguess in profiles:
         profiles = [bestguess] + profiles
      chosen = 'none'
      for profile in profiles:
         self._config.update('profile', profile)
         addr_space = utils.load_as(self._config, astype='any')
         if hasattr(addr_space, 'dtb'):
            chosen = profile
            break
      if bestguess != chosen:
         print bestguess, chosen
      volmagic = obj.VolMagic(addr_space)
      print addr_space
      kdbgoffset = volmagic.KDBG.v()
      self._kdbg = obj.Object("_KDDEBUGGER_DATA64", offset = kdbgoffset, vm = addr_space)
      self._config.update('kdbg', self._kdbg.obj_offset)
      self._astype = addr_space

     

   # Following functions use lambda to create keys for the dict
   # Default ones are based on offset
   # For example, to use pid as key: self.procMapFromPSList(key=lambda x: int(x.UniqueProcessId))
   # concerning psscan, it directly works on physical offset, so bypass vmtop

   def __createProcessTree(self):
      self._pslist = [proc for proc in taskmods.PSList(self._config).calculate()]
      self._psscan = filescan.PSScan(self._config).calculate()
      self._thscan = self.__procMapFromThrScan()
      poffsets = [p.obj_vm.vtop(p.obj_offset) for p in self._pslist]
      psorphaned = []
      phidden = []
      print len(poffsets), "--", len(self._pslist)
         #for p in self._pslist:
         #   print p.UniqueProcessId, p.InheritedFromUniqueProcessId
      for p in self._thscan.values():
         if p.obj_offset not in poffsets:
            print p.ExitTime, p.ImageFileName
            #if p.ExitTime != 0:
            #   psorphaned.append(p)
            #else:
            #   phidden.append(p)
      print "PHIDDEN:", len(phidden)
         #print len(psorphaned)
      self.__mainProcNode = Node("Processes", 0, self.root, self)
      self.__mainProcNode.__disown__()
      procmap = {}
      for proc in self._pslist:
         #if procmap.has_key(proc.UniqueProcessId):
         procmap[int(proc.UniqueProcessId)] = proc
      self.__createActiveProcessTree(procmap)
      for p in psorphaned:
         if p.InheritedFromUniqueProcessId in self.__psactivetree.keys():
            print "Found :)"
         else:
            print "Fucking orphaned one !"
         #print p.ImageFileName, p.UniqueProcessId, p.InheritedFromUniqueProcessId
      
      #print "GATHERED IDs:"
      #print "  scan_set    :", sorted(scan_set)
      #print "  list_set    :", sorted(list_set)
      #print "  thr_set     :", sorted(thr_set)
      #print "  pspcid_set  :", sorted(pspcid_set)

      #print "=" * 42

      #for off in list_set:
      #   uid = str(self.pslist[off].UniqueProcessId)
      #   name = self.pslist[off].ImageFileName
      #   ctime = str(self.pslist[off].CreateTime)
      #   etime = str(self.pslist[off].ExitTime)
      #   cr3 = self.pslist[off].Pcb.DirectoryTableBase
      #   print uid + " " * (10-len(uid)) + name + " " * (30-len(name)) + ctime + " "*(12-len(ctime)) + etime + " "*(12-len(etime)) + hex(cr3)
            
      #print phidden
      #for hidden in phidden:
      #   process = self.psscanid[int(hidden)]
      #   print process.ImageFileName, process.UniqueProcessId, process.ExitTime


   def __procMapFromThrScan(self, key=lambda x: x.obj_vm.vtop(x.obj_offset)):
      ret = dict()

      for ethread in modscan.ThrdScan(self._config).calculate():
         if ethread.ExitTime != 0:
            continue
         process = None
         if hasattr(ethread.Tcb, 'Process'):
            process = ethread.Tcb.Process.dereference_as('_EPROCESS')
         elif hasattr(ethread, 'ThreadsProcess'):
            process = ethread.ThreadsProcess.dereference()            
         if (process and process.ExitTime == 0 and
             process.UniqueProcessId > 0 and
             process.UniqueProcessId < 65535):
            ret[key(process)] = process
      return ret


   def __procMapFromPspcid(self, key=lambda x: x.obj_vm.vtop(x.obj_offset)):
      ret = dict()
      if hasattr(self, "_kdbg"):
         PspCidTable = self._kdbg.PspCidTable.dereference().dereference()

         for handle in PspCidTable.handles():
            if handle.get_object_type() == "Process":
               process = handle.dereference_as("_EPROCESS")
               ret[key(process)] = process
      return ret


   def __createActiveProcessTree(self, processes):
      """
      Active Process Tree is created based on pslist
      """
      self.__psactivetree = {}

      def createActiveProcessNode(parent, inherited_from):
         for proc in processes.values():
            if proc.InheritedFromUniqueProcessId == inherited_from:
               n = WinProcNode(str(proc.ImageFileName), parent, self, proc)
               self.__psactivetree[proc.UniqueProcessId] = n
               del processes[int(proc.UniqueProcessId)]
               #count += 1
               createActiveProcessNode(n, int(proc.UniqueProcessId))
               #self.stateinfo = "Step 1: creating active process tree: " + str(count) + "/" + str(total)
               #print self.stateinfo

      while len(processes.keys()) > 0:
         keys = processes.keys()
         root = self.find_root(processes, keys[0])
         createActiveProcessNode(self.__mainProcNode, root)


   def find_root(self, processes, pid):
      seen = set()
      print processes.keys()
      while pid in processes and pid not in seen:
         seen.add(pid)
         print "\t", pid
         pid = int(processes[pid].InheritedFromUniqueProcessId)
      print "root: ", pid
      return pid


class mvolatility(Module):
   """Analyse windows ram dump"""
   def __init__(self):
      if not with_volatility:
         raise RuntimeError("Volatility not found. Please install it")
      Module.__init__(self, "mvolatility", Volatility)
      registry.PluginImporter()
      self.conf.addArgument({"name": "file",
                             "description": "Dump to analyse",
                             "input": Argument.Required|Argument.Single|typeId.Node
                             })

      self.conf.addArgument({"name": "hdd_base",
                             "description": "Hard Disk Drive mount point associated to this memory dump",
                             "input": Argument.Optional|Argument.Single|typeId.Node
                             })

      self.conf.addArgument({"name": "profile",
                             "description": "Profile to use",
                             "input": Argument.Optional|Argument.Single|typeId.String,
                             "parameters": {"type": Parameter.NotEditable,
                                            "predefined": [ p.__name__ for p in registry.get_plugin_classes(obj.Profile).values() ]}
                             })
      self.conf.description = "Analyse windows ram dump"
      self.tags = "Volatile memory"
      self.icon = ":dev_ram.png"
