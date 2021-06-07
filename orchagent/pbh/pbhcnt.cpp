// Includes -----------------------------------------------------------------------------------------------------------

#include <limits>
#include <string>

#include "pbhcnt.h"

using namespace swss;

//----

//##include <cstddef>
//##include <cstdint>
//#include <cstring>

//#include <unordered_map>
//#include <sstream>


//#include <vector>

//#include "aclorch"



//#include "ipaddress.h"
//#include "tokenize.h"




// PBH Container ------------------------------------------------------------------------------------------------------

PbhContainer::PbhContainer(const std::string &key, const std::string &op) noexcept
{
    this->key = key;
    this->op = op;
}

const std::uint64_t& PbhContainer::getRefCount() const
{
    return this->refCount;
}

void PbhContainer::incrementRefCount()
{
    static const std::uint64_t max = std::numeric_limits<std::uint64_t>::max();

    if (this->refCount < max)
    {
        this->refCount++;
    }
}

void PbhContainer::decrementRefCount()
{
    static const std::uint64_t min = std::numeric_limits<std::uint64_t>::min();

    if (this->refCount > min)
    {
        this->refCount--;
    }
}

void PbhContainer::clearRefCount()
{
    this->refCount = 0;
}

// PBH Table ----------------------------------------------------------------------------------------------------------

PbhTable::PbhTable(const std::string &key, const std::string &op) noexcept :
    PbhContainer(key, op)
{

}

// PBH Rule -----------------------------------------------------------------------------------------------------------

PbhRule::PbhRule(const std::string &key, const std::string &op) noexcept :
    PbhContainer(key, op)
{

}

// PBH Hash -----------------------------------------------------------------------------------------------------------

PbhHash::PbhHash(const std::string &key, const std::string &op) noexcept :
    PbhContainer(key, op)
{

}

const sai_object_id_t& PbhHash::getOid() const noexcept
{
    return this->oid;
}

void PbhHash::setOid(const sai_object_id_t &oid) noexcept
{
    this->oid = oid;
}

// PBH hash field -----------------------------------------------------------------------------------------------------

PbhHashField::PbhHashField(const std::string &key, const std::string &op) noexcept :
    PbhContainer(key, op)
{

}

const sai_object_id_t& PbhHashField::getOid() const noexcept
{
    return this->oid;
}

void PbhHashField::setOid(const sai_object_id_t &oid) noexcept
{
    this->oid = oid;
}
