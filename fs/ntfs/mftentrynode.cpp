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

#include "mftentrynode.hpp"
#include "bootsector.hpp"
#include "ntfs.hpp"
#include "mftattribute.hpp"
#include "mftattributecontent.hpp"

//MFTRecord :: public MFTEntryNode
// MFTRecord(NTFS* ntfs, uint64_t record Number, ...
// 
// IndexNode :: public MFTEntryNode
// penser qu il n'y a pas que les attributs qui sont specialiser mais aussi les 'data'



//MFTEntryNode::MFTEntryNode(NTFS* ntfs, Node* fsNode, uint64_t offset, std::string name, Node* parent = NULL) : Node(name, ntfs->bootSectorNode()->MFTRecordSize(), parent, ntfs) //ajouter le parent XXX
//XXX bizare en lisant de la taille d une mft 1024 ca marche bcp mieux car si non si la mft fait 10mo 
//on alloue pour chaque node 10mo mais si on la lit une fois en entier c pas mieux ? c ce qu on fait au debut pourtant donc la on fait 2 fois les fixup c normal ou c t juste un test ???
MFTEntryNode::MFTEntryNode(NTFS* ntfs, Node* fsNode, uint64_t offset, std::string name, Node* parent = NULL) : Node(name, 1024, parent, ntfs) //ajouter le parent
{
  VFile*	vfile = NULL;

  //this->__ntfs->setStateInfo("Parsing MFT "); //+ this->name() ? 
  this->__fsNode = fsNode;
  this->__ntfs = ntfs;
  this->__offset = offset;
  //std::cout << "MFTEntryNode::MFTEntryNode new MFTEntry" << std::endl;
  this->__MFTEntry = new MFTEntry; 
  this->__state = 0;
//XXX
//cache mfso ...
//READ sur self possible uniquement car la struct est plus petite que l endroit du premier fixup
//vfile = this->open(); //XXX ossible car si non fixup value sera la n imp
//cout << "MFTEntryNode::MFTEntryNode
  vfile = this->fsNode()->open();

  if (vfile->seek(this->offset()) != this->offset())
  {
    vfile->close();
    throw std::string("Can't seek to MFT entry structure");
  }
  if  (vfile->read((void *) (this->__MFTEntry), sizeof(MFTEntry)) != sizeof(MFTEntry))
  {
    vfile->close();
    throw std::string("Can't read MFT Entry structure");
  }
  vfile->close();

  this->__state++;
//hum hum a delete

  std::vector<MFTAttribute* > mftAttributes = this->MFTAttributes();
  std::vector<MFTAttribute* >::iterator	mftAttribute;
  mftAttribute = mftAttributes.begin();
  for (; mftAttribute != mftAttributes.end(); mftAttribute++)
     if (*mftAttribute != NULL)
       delete *mftAttribute;    
//for delte etc /????
}

MFTEntryNode::~MFTEntryNode()
{
  if (this->__MFTEntry != NULL)
  {
     delete this->__MFTEntry;
     this->__MFTEntry = NULL;
  }
//  if (this->attributeBuff
}


//XXX each call doit delete la list des __mftattributes
std::vector<MFTAttribute*>	MFTEntryNode::MFTAttributes(void)
{
  std::vector<MFTAttribute*>	mftAttributes; //delete std::vector delete bien les pointeurs ?
  uint16_t offset = this->firstAttributeOffset();

  try 
  {
    while (offset < this->usedSize()) //don't check delete attribute or use allocatedSize and do diff /take car unusedsiz could be invalid
    {
       MFTAttribute* mftAttr = this->__MFTAttribute(offset); //XXX new must delete all !
       mftAttributes.push_back(mftAttr); 
       //std::cout << "New attribute found ID " << mftAttr->ID() << " type ID " << mftAttr->typeID() << " lenght" << mftAttr->length() << " name length " << mftAttr->nameLength() << " is resident " << mftAttr->isResident() <<std::endl;
       if (mftAttr->length() == 0)
	 break;
       offset += mftAttr->length(); //take care could be invalid
    }
  }
  catch(std::string error)
  {
  }
  return (mftAttributes);
}

//XXX caller must deltte !!
std::vector<MFTAttribute*>	MFTEntryNode::MFTAttributesType(uint32_t typeID)
{
  std::vector<MFTAttribute* >		mftAttributes; //delete std::vector delete bien les pointeurs ?
  std::vector<MFTAttribute* >		mftAttributesType; //delete std::vector delete bien les pointeurs ?
  std::vector<MFTAttribute* >::iterator	mftAttribute;

  mftAttributes = this->MFTAttributes();
  mftAttribute = mftAttributes.begin();
  for (; mftAttribute != mftAttributes.end(); mftAttribute++)
     if ((*mftAttribute)->typeID() == typeID)
       mftAttributesType.push_back(*mftAttribute);
     else
       delete *mftAttribute;
  return (mftAttributesType);
}


//renvoie UN NEW DOIT ETRE DELETE QUQU PART !!
MFTAttribute*			MFTEntryNode::__MFTAttribute(uint16_t offset) // VFile ? 
{
  MFTAttribute*	mftAttribute = NULL;  

  //std::cout << "MFTEntryNode::__MFTAttribute create new MFTAttribute" << std::endl;
  mftAttribute = new MFTAttribute(this, offset);

  return (mftAttribute);
}

uint64_t	MFTEntryNode::_attributesState(void)
{
//XXX les virtuels doivent pas etre aPPELLER DS LE CONSTRUCTEUR 
//std::cout << "MFTEntryNode::_attributesState " << std::endl;
  return this->__state;
}

uint64_t	MFTEntryNode::fileMappingState(void)
{
//XXX les virtuels doivent pas etre aPPELLER DS LE CONSTRUCTEUR 
//std::cout << "MFTEntryNode::_fileMappingState " << std::endl;
  return this->__state;
}

//XXX optimiser un read si possible ou en FSO et pas MFSO !
// peut pas renvoyer les push mais plus rapide que faire des tonnes de push

void		MFTEntryNode::fileMapping(FileMapping *fm)
{
  uint64_t offset = 0;
  uint16_t sectorSize = this->__ntfs->bootSectorNode()->bytesPerSector();
//push bcp jamais ds le ache pourquoi doit relire avec le fixup alors qu on lit deja toute la mft
// pas plutot la lire un seul fois car la double fixup etc /??
  //printf("mftentrynode %llu\n",this->size());
  while (offset < this->size()) //create filemapping util size
  {
    if (this->size() - offset >= sectorSize) //
    {
	    //std::cout << "MFTEntryNode::FileMapping push" << std::endl;
      //push a l offset du bock ds a nouvelle node(offset)
      //la size du block a push sizeof(uint16_T)
      //push la node sur la quel on va lire -> le root passer au module
      // va lire this->offset() -> donc offset de la mft + offset actuel 0, 500, 
      // la size et this
      //printf("push !\n");
      fm->push(offset, sectorSize - sizeof(uint16_t), this->fsNode(), this->offset() + offset);
      offset += sectorSize - sizeof(uint16_t);
      fm->push(offset, //push l offset courant ds la new node ...
	       sizeof(uint16_t), //push des block de 2 ??????
	       this->__ntfs->fsNode(), //push la node
		
		

	       this->offset() + this->fixupArrayOffset() + sizeof(uint16_t) + (sizeof(uint16_t) * (offset / sectorSize)));
	       //0x1000 -> demaragede la mft 
	      //fixup arrayoffset -> offsetDufixup -> 0xff 
	      // + 2 
	      // + 2 * (offset/ 4096)

      offset += sizeof(uint16_t); 
    }
    else //push le dernier block si non aligner a la taille d un secteur
    {
      fm->push(offset, this->size() - offset, this->fsNode(), this->offset() + offset);
      offset += this->size() - offset;
    }
  }
}



Attributes		MFTEntryNode::_attributes(void)
{
  Attributes	attrs;

  //MAP_ATTR("Sector number", this->sectorNumber())
//MAP_ATTR("Entry number") 0 read sur une autre node ..
  MAP_ATTR("Offset", this->offset())
  MAP_ATTR("Signature", this->signature())
  MAP_ATTR("Used size", this->usedSize())
  MAP_ATTR("Allocated size", this->allocatedSize())
  MAP_ATTR("First attribute offset", this->firstAttributeOffset())

  std::vector<MFTAttribute*>		mftAttributes = this->MFTAttributes();
  std::vector<MFTAttribute*>::iterator  mftAttribute = mftAttributes.begin();
  for (; mftAttribute != mftAttributes.end(); mftAttribute++)
  {
    try 
    {
      MFTAttributeContent* mftAttributeContent = (*mftAttribute)->content();	
      MAP_ATTR(mftAttributeContent->typeName(), mftAttributeContent->_attributes());
      delete mftAttributeContent;
      delete (*mftAttribute);
    }
    catch (vfsError e)
    {
	cout << e.error << endl;
    }
  }
  //delete la map d attribute;
  return (attrs);
}

void		MFTEntryNode::validate(void)
{
  if ((this->signature() != MFT_SIGNATURE_FILE) && (this->signature() != MFT_SIGNATURE_BAAD))
    throw vfsError(std::string("MFT signature is invalid")); 
    //if baad ? setbad ca se fait pas la 
// read & check fixup value ? 
}

NTFS*		MFTEntryNode::ntfs(void)
{
  return (this->__ntfs);
}

Node*		MFTEntryNode::fsNode(void)
{
  return (this->__fsNode);
}
/*
uint64_t	MFTEntryNode::sectorNumber(void)
{
  return (this->__sectorNumber);
}

uint64_t	MFTEntryNode::offset(void)
{
  return (this->sectorNumber() * this->__ntfs->bootSectorNode()->clusterSize());
}
*/

uint64_t	MFTEntryNode::offset(void)
{
  return (this->__offset);
}

uint32_t	MFTEntryNode::signature(void)
{
  if (this->__MFTEntry != NULL)
    return (this->__MFTEntry->signature);
  throw vfsError(std::string("ntfs::MFTEntryNode::signature no MFTEntry."));
}

uint32_t	MFTEntryNode::usedSize(void)
{
  if (this->__MFTEntry != NULL)
    return (this->__MFTEntry->usedSize);
  throw vfsError(std::string("ntfs::MFTEntryNode::useSize no MFTEntry."));
}

uint32_t	MFTEntryNode::allocatedSize(void)
{
  if (this->__MFTEntry != NULL)
    return (this->__MFTEntry->allocatedSize);
  throw vfsError(std::string("ntfs::MFTEntryNode::allocatedSize no MFTEntry."));
}

uint16_t	MFTEntryNode::firstAttributeOffset(void)
{
  if (this->__MFTEntry != NULL) 
    return (this->__MFTEntry->firstAttributeOffset);
  throw vfsError(std::string("ntfs::MFTEntryNode::attributeOffset no MFTEntry."));
}

uint16_t	MFTEntryNode::fixupArrayOffset(void)
{
  if (this->__MFTEntry != NULL) 
    return (this->__MFTEntry->fixupArrayOffset);
  throw vfsError(std::string("ntfs::MFTEntryNode::fixupArrayOffset no MFTEntry."));
}

/* -1 because we skip signature */
uint16_t	MFTEntryNode::fixupArrayEntryCount(void)
{
  if (this->__MFTEntry != NULL) 
    return (this->__MFTEntry->fixupArrayEntryCount - 1);
  throw vfsError(std::string("ntfs::MFTEntryNode::fixupArratEntryCount no MFTEntry."));
}
