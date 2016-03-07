#ifndef __streamvfile_hpp__
#define __streamvfile_hpp__

#include "dstruct.hpp"
#include "protocol/dcppobject.hpp"

namespace DFF
{
  class VFile;
}

using namespace Destruct;

class StreamVFile : public DCppObject<StreamVFile>
{
public:
  StreamVFile(DStruct* dstruct, DFF::VFile* vfile);
  StreamVFile(const StreamVFile& copy);

  DBuffer  read(DValue const& args); 
  //DInt64   write(DValue const& args);
  void     flush(void);
  void     seek(DValue const& args);
  DUInt64  size(void);
  DUInt64  tell(void);
 
protected:
  ~StreamVFile();
private:
  DFF::VFile*        __vfile;
public:
  RealValue<DFunctionObject* > _read, _seek, _size, _tell; //_write, _flush

  static size_t ownAttributeCount()
  {
    return (4);
  }

  static DAttribute* ownAttributeBegin()
  {
    static DAttribute  attributes[] = 
    {
       DAttribute(DType::DBufferType, "read",  DType::DInt64Type), 
       //DAttribute(DType::DInt64Type,  "write", DType::DBufferType),
       //DAttribute(DType::DNoneType, "flush", DType::DNoneType),
       DAttribute(DType::DUInt64Type, "size", DType::DUInt64Type),
       DAttribute(DType::DNoneType, "seek", DType::DUInt64Type),
       DAttribute(DType::DUInt64Type, "tell", DType::DNoneType),
    };
    return (attributes);
  }

  static DPointer<StreamVFile>* memberBegin()
  {
    static DPointer<StreamVFile> memberPointer[] = 
    {
       DPointer<StreamVFile>(&StreamVFile::_read, &StreamVFile::read),
       //DPointer<StreamVFile>(&StreamVFile::_write, &StreamVFile::write),
       //DPointer<StreamVFile>(&StreamVFile::_flush, &StreamVFile::flush),
       DPointer<StreamVFile>(&StreamVFile::_size, &StreamVFile::size),
       DPointer<StreamVFile>(&StreamVFile::_seek, &StreamVFile::seek),
       DPointer<StreamVFile>(&StreamVFile::_tell, &StreamVFile::tell),
    };
    return (memberPointer);
  }

  static DAttribute* ownAttributeEnd()
  {
    return (ownAttributeBegin() + ownAttributeCount());
  }

  static DPointer<StreamVFile>*  memberEnd()
  {
    return (memberBegin() + ownAttributeCount());
  } 
};

#endif
