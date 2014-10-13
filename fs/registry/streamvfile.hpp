#ifndef __streamvfile_hpp__
#define __streamvfile_hpp__

#include "registry_common.hpp"
#include "vfile.hpp"

using namespace Destruct;

class StreamVFile : public DStream
{
public:
                    StreamVFile(VFile* vfile, DStruct* dstruct);
                    StreamVFile(DStruct* dstruct, DValue const &args);
                    StreamVFile(const StreamVFile& copy);
                    ~StreamVFile();
  DStream&          read(char*  buff, uint32_t size);
  DStream&          write(const char* buff, uint32_t size);
  DStream&          seek(int64_t pos);
  int64_t           tell(void);
private:
  VFile*            __vfile;
};

#endif
