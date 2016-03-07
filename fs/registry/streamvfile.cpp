#include "vfile.hpp"
#include "node.hpp"
#include "drealvalue.hpp"

#include "streamvfile.hpp"

using namespace Destruct;

StreamVFile::StreamVFile(DStruct* dstruct, DFF::VFile* vfile) : DCppObject<StreamVFile>(dstruct, RealValue<DObject*>(DNone)), __vfile(vfile)
{
  this->init();
}

StreamVFile::StreamVFile(const StreamVFile& copy) : DCppObject<StreamVFile>(copy)
{
  this->init();
}

/**
 *  Take care if not destroyed it will not be flushed !
 */
StreamVFile::~StreamVFile()
{
  //this->__stream.close();
  //this->__vfile.close();
 //delete this->__vfile;
}

DBuffer StreamVFile::read(DValue const& args)
{
  DInt64 size = args.get<DInt64>();
  if (size == 0)
    return DBuffer(NULL, 0);

 
  DBuffer buffer((int32_t)size);
  this->__vfile->read(buffer.data(), size);

  return (buffer);
}

void    StreamVFile::seek(DValue const& args)
{
  DUInt64 pos = args.get<DUInt64>();
  this->__vfile->seek(pos);
}

DUInt64 StreamVFile::size(void)
{
  return (this->__vfile->node()->size());
}

DUInt64 StreamVFile::tell(void)
{
  return (this->__vfile->tell());
}

//DStream& StreamVFile::write(const char* buff, uint32_t size) 
//{
//throw DException("Can't write on StreamVFile");
//}
