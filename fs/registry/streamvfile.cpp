#include "streamvfile.hpp"

using namespace Destruct;

StreamVFile::StreamVFile(VFile* vfile, DStruct* dstruct): DStream(dstruct), __vfile(vfile)
{
  this->init();
}

StreamVFile::StreamVFile(DStruct* dstruct, DValue const& args): DStream(dstruct), __vfile(NULL)
{
  this->init();
}

StreamVFile::StreamVFile(const StreamVFile& copy) : DStream(copy), __vfile(copy.__vfile)
{
  this->init();
}

StreamVFile::~StreamVFile()
{
  this->__vfile->close();
  delete this->__vfile;
}

DStream& StreamVFile::read(char*  buff, uint32_t size)
{
  this->__vfile->read(buff, size);
  return (*this);
}

DStream& StreamVFile::write(const char* buff, uint32_t size) 
{
  throw DException("Can't write on StreamVFile");
}

DStream& StreamVFile::seek(int64_t pos) //declare en virtuel ds dstream
{
  this->__vfile->seek(pos);
  return (*this);
} 

int64_t  StreamVFile::tell(void)
{
  return (this->__vfile->tell());
}
