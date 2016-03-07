#include "datetime.hpp"

#include "registrynode.hpp"

RegfNode::RegfNode(DObject* regf, Node* parent, fso* fsobj) : Node("", 0, parent, fsobj)
{
//  this->__name = regf->call("name").get<DUnicodeString>(); 
  this->__name = "regf"; //XXX
}

KeyNode::KeyNode(DObject* key, Node* parent, fso* fsobj) : Node("", 0, parent, fsobj)
{
  this->__name = key->getValue("name").get<DUnicodeString>();
  this->__timeStamp = key->getValue("timestamp"); 
}

Attributes      KeyNode::_attributes(void)
{
 Attributes attr;

 attr["modified"] = Variant_p(new Variant(new MS64DateTime(this->__timeStamp)));

 return (attr);
}


ValueNode::ValueNode(DObject* value, Node* parent, fso* fsobj) : Node("", 0, parent, fsobj)
{
  this->__name = value->getValue("name").get<DUnicodeString>();
  this->__dataType = value->getValue("dataType");
}

Attributes      ValueNode::_attributes(void)
{
  Attributes attr;

  attr["type"] = Variant_p(new Variant(this->registryType(this->__dataType)));
//if type ...
//this->open->read() ?
  //attr["data"] = Variant_p(new Variant());

  return (attr);
}

std::string  ValueNode::icon(void)
{
  return (":password.png");
}
