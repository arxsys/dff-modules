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

#ifndef __NTFS_COMMON_HH__
#define __NTFS_COMMON_HH__

#include <typeinfo>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dstructs.hpp"
#include "drealvalue.hpp"
#include "dvalue.hpp"
#include "dobject.hpp"
#include "dnullobject.hpp"
#include "protocol/dcppobject.hpp"
#include "export.hpp"
#include "vfs.hpp"
#include "mfso.hpp"
#include "node.hpp"
#include "variant.hpp"
#include "typesconv.hpp"

#define NEW_VARIANT(x) Variant_p(new Variant(x))
#define MAP_ATTR(x, y) attrs[x] = NEW_VARIANT(y);

#endif 
