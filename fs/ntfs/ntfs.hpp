/*
 * DFF -- An Open Source Digital Forensics Framework
 * Copyright (C) 2009-2011 ArxSys
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 *  
 * See http: *www.digital-forensic.org for more information about this
 * project. Please do not directly contact any of the maintainers of
 * DFF for assistance; the project provides a web site, mailing lists
 * and IRC channels for your use.
 * 
 * Author(s):
 *  Solal Jacob <sja@digital-forensic.org>
 */

#ifndef __NTFS_HH__
#define __NTFS_HH__

#include "ntfs_common.hpp"

class NTFSOpt;
class BootSectorNode;
class MFTNode;
class MFTEntryManager;

class NTFS : public mfso
{
private:
  NTFSOpt*              __opt;
  BootSectorNode*       __bootSectorNode;
  MFTEntryManager*      __mftManager;
  Node*                 __rootDirectoryNode;
  Node*                 __orphansNode;
  Node*                 __unallocatedNode;
public:
                        NTFS();
                        ~NTFS();
  virtual void          start(Attributes args);
  void                  setStateInfo(const std::string&);
  NTFSOpt*              opt(void) const;
  Node*                 fsNode(void) const;
  Node*                 rootDirectoryNode(void) const;
  BootSectorNode*       bootSectorNode(void) const;
  Node*                 orphansNode(void) const;
  Node*                 unallocatedNode(void) const;
  MFTEntryManager*      mftManager(void) const;
  /*
   *  Need file mapping && bufer read for decompression
   */
  int32_t 	        vread(int fd, void *buff, unsigned int size);
};

#endif
