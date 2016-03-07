#include "node.hpp"
#include "variant.hpp"
#include "dobject.hpp"

using namespace DFF;
using namespace Destruct;

class RegfNode : public Node
{
public:
  RegfNode(DObject* regf, Node* parent, fso* fsobj);
};

class KeyNode : public Node
{
public:
  KeyNode(DObject* key, Node* parent, fso* fsobj);
  Attributes _attributes(void);
private:
  DUInt64 __timeStamp;
 //filemapping offset ? push nk not very usefull but for forensics ...
};

class ValueNode : public Node
{
public:
  ValueNode(DObject* value, Node* parent, fso* fsobj);
  std::string   icon(void);
  Attributes _attributes(void);
private:
  DUInt32 __dataType;

  static std::string registryType(uint32_t dataType)
  {
    static std::string registryType[] = { 
                                          "REG_NONE",
                                          "REG_SZ",
                                          "REG_EXPAND_SZ",
                                          "REG_BINARY",
                                          "REG_DWORD",
                                          "REG_DWORD_BIG_ENDIAN",
                                          "REG_LINK",
                                          "REG_MULTI_SZ",
                                          "REG_RESOURCE_LIST",
                                          "REG_FULL_RESOURCE_DESCRIPTON",
                                          "REG_RESOURCE_REQUIEREMENTS_LIST",
                                          "REG_QWORD",
                                        }; 
    return registryType[dataType]; 
  }
 
//filemapping
//attribute
};
