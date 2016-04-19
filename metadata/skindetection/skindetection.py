# DFF -- An Open Source Digital Forensics Framework
# Copyright (C) 2009-2013 ArxSys
# 
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
#  Christophe Malinge <cma@digital-forensic.org>

__dff_module_skindetection_version__ = "1.0.0"

from PIL import Image

from dff.api.vfs.libvfs import TagsManager
from dff.api.module.script import Script 
from dff.api.module.module import Module
from dff.api.types.libtypes import Argument, typeId

class SkinDetection(Script):
  #from http://www.naun.org/multimedia/NAUN/computers/20-462.pdf
  def __init__(self):
   Script.__init__(self, "skindetection")

  def detectSkin(self, node):
    vfile = node.open()
    img = Image.open(vfile)
    if not img.mode == 'YCbCr':
        img = img.convert('YCbCr')
    img.thumbnail((256, 256), Image.ANTIALIAS)
    ycbcr_data = img.getdata() 
    imageWidth, imageHeight = img.size #add to image attribute
    vfile.close()
    threshold = 0.3 #percentage of skin to detect
    count = 0
    #try with hsv too
    for i,ycbcr in enumerate(ycbcr_data):
        y,cb,cr = ycbcr
        #if 86 <= cb <= 127 and 130 <= cr < 168:
        if 80 <= cb <= 120 and 133 <= cr <= 173:
            count += 1
    if count > threshold*imageWidth*imageHeight:
      return True
    return False
        
  def start(self, args):
    try:
      node = args['file'].value()
      if self.detectSkin(node):
        node.setTag("explicit")
    except Exception as e:
      print "Skin detection error on node ", str(node.absolute()) , " :"
      print str(e)

class skindetection(Module): 
  """This module try to detect skin in pictures and tags picture with the 'explicit' tag if this is the case.
The result is not accurate and have a certain percent of false positive."""
  def __init__(self):
    Module.__init__(self, "skindetection", SkinDetection)
    self.conf.addArgument({"name": "file",
                           "description": "Parses metadata of this file",
                           "input": Argument.Required|Argument.Single|typeId.Node})
    self.conf.addConstant({"name": "mime-type", 
 	                   "type": typeId.String,
 	                   "description": "managed mime type",
 	                   "values": ["image"]})
    #self.flags = ["single"] slower ?
    self.tags = "Metadata"
    self.icon = ":meeting"
    tagsManager = TagsManager.get()
    tagsManager.add('explicit', 255, 85, 127)
