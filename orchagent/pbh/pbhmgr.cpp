// includes -----------------------------------------------------------------------------------------------------------

#include <cstdint>

#include <unordered_map>
#include <unordered_set>
#include <exception>
#include <string>

#include "ipaddress.h"
#include "converter.h"
#include "tokenize.h"
#include "logger.h"

#include "pbhmgr.h"

using namespace swss;

// defines ------------------------------------------------------------------------------------------------------------

#define PBH_TABLE_INTERFACE_LIST "interface_list"
#define PBH_TABLE_DESCRIPTION    "description"

#define PBH_RULE_PACKET_ACTION_SET_ECMP_HASH "SET_ECMP_HASH"
#define PBH_RULE_PACKET_ACTION_SET_LAG_HASH  "SET_LAG_HASH"

#define PBH_RULE_FLOW_COUNTER_ENABLED  "ENABLED"
#define PBH_RULE_FLOW_COUNTER_DISABLED "DISABLED"

#define PBH_RULE_PRIORITY         "priority"
#define PBH_RULE_GRE_KEY          "gre_key"
#define PBH_RULE_IP_PROTOCOL      "ip_protocol"
#define PBH_RULE_IPV6_NEXT_HEADER "ipv6_next_header"
#define PBH_RULE_L4_DST_PORT      "l4_dst_port"
#define PBH_RULE_INNER_ETHER_TYPE "inner_ether_type"
#define PBH_RULE_HASH             "hash"
#define PBH_RULE_PACKET_ACTION    "packet_action"
#define PBH_RULE_FLOW_COUNTER     "flow_counter"

#define PBH_HASH_HASH_FIELD_LIST "hash_field_list"

#define PBH_HASH_FIELD_HASH_FIELD_INNER_IP_PROTOCOL "INNER_IP_PROTOCOL"
#define PBH_HASH_FIELD_HASH_FIELD_INNER_L4_DST_PORT "INNER_L4_DST_PORT"
#define PBH_HASH_FIELD_HASH_FIELD_INNER_L4_SRC_PORT "INNER_L4_SRC_PORT"
#define PBH_HASH_FIELD_HASH_FIELD_INNER_DST_IPV4    "INNER_DST_IPV4"
#define PBH_HASH_FIELD_HASH_FIELD_INNER_SRC_IPV4    "INNER_SRC_IPV4"
#define PBH_HASH_FIELD_HASH_FIELD_INNER_DST_IPV6    "INNER_DST_IPV6"
#define PBH_HASH_FIELD_HASH_FIELD_INNER_SRC_IPV6    "INNER_SRC_IPV6"

#define PBH_HASH_FIELD_HASH_FIELD  "hash_field"
#define PBH_HASH_FIELD_IP_MASK     "ip_mask"
#define PBH_HASH_FIELD_SEQUENCE_ID "sequence_id"

// constants ----------------------------------------------------------------------------------------------------------

static const std::unordered_map<std::string, sai_acl_entry_attr_t> pbhRulePacketActionMap =
{
    { PBH_RULE_PACKET_ACTION_SET_ECMP_HASH, SAI_ACL_ENTRY_ATTR_ACTION_SET_ECMP_HASH_ID },
    { PBH_RULE_PACKET_ACTION_SET_LAG_HASH,  SAI_ACL_ENTRY_ATTR_ACTION_SET_LAG_HASH_ID  }
};

static const std::unordered_map<std::string, bool> pbhRuleFlowCounterMap =
{
    { PBH_RULE_FLOW_COUNTER_ENABLED,  true  },
    { PBH_RULE_FLOW_COUNTER_DISABLED, false }
};

static const std::unordered_map<std::string, sai_native_hash_field_t> pbhHashFieldHashFieldMap =
{
    { PBH_HASH_FIELD_HASH_FIELD_INNER_IP_PROTOCOL, SAI_NATIVE_HASH_FIELD_INNER_IP_PROTOCOL },
    { PBH_HASH_FIELD_HASH_FIELD_INNER_L4_DST_PORT, SAI_NATIVE_HASH_FIELD_INNER_L4_DST_PORT },
    { PBH_HASH_FIELD_HASH_FIELD_INNER_L4_SRC_PORT, SAI_NATIVE_HASH_FIELD_INNER_L4_SRC_PORT },
    { PBH_HASH_FIELD_HASH_FIELD_INNER_DST_IPV4,    SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4    },
    { PBH_HASH_FIELD_HASH_FIELD_INNER_SRC_IPV4,    SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4    },
    { PBH_HASH_FIELD_HASH_FIELD_INNER_DST_IPV6,    SAI_NATIVE_HASH_FIELD_INNER_DST_IPV6    },
    { PBH_HASH_FIELD_HASH_FIELD_INNER_SRC_IPV6,    SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV6    }
};

// PBH manager  -------------------------------------------------------------------------------------------------------

std::uint8_t PbhManager::toUInt8(const std::string &hexStr)
{
    if (hexStr.substr(0, 2) != "0x")
    {
        throw std::invalid_argument("Invalid argument: '" + hexStr + "'");
    }

    return to_uint<std::uint8_t>(hexStr);
}

std::uint16_t PbhManager::toUInt16(const std::string &hexStr)
{
    if (hexStr.substr(0, 2) != "0x")
    {
        throw std::invalid_argument("Invalid argument: '" + hexStr + "'");
    }

    return to_uint<std::uint16_t>(hexStr);
}

std::uint32_t PbhManager::toUInt32(const std::string &hexStr)
{
    if (hexStr.substr(0, 2) != "0x")
    {
        throw std::invalid_argument("Invalid argument: '" + hexStr + "'");
    }

    return to_uint<std::uint32_t>(hexStr);
}

template <typename T>
bool PbhManager::hasDependencies(const T &obj) const
{
    if (obj.getRefCount() > 0)
    {
        return true;
    }

    return false;
}

template bool PbhManager::hasDependencies(const PbhTable &obj) const;
template bool PbhManager::hasDependencies(const PbhRule &obj) const;
template bool PbhManager::hasDependencies(const PbhHash &obj) const;
template bool PbhManager::hasDependencies(const PbhHashField &obj) const;

template<>
bool PbhManager::validateDependencies(const PbhRule &obj) const
{
    const auto &tCit = this->tableMap.find(obj.table);
    if (tCit == this->tableMap.cend())
    {
        return false;
    }

    const auto &hCit = this->hashMap.find(obj.hash.value);
    if (hCit == this->hashMap.cend())
    {
        return false;
    }

    return true;
}

template<>
bool PbhManager::validateDependencies(const PbhHash &obj) const
{
    for (const auto &cit : obj.hash_field_list.value)
    {
        const auto &hfCit = this->hashFieldMap.find(cit);
        if (hfCit == this->hashFieldMap.cend())
        {
            return false;
        }
    }

    return true;
}

template<>
bool PbhManager::addDependencies(const PbhRule &obj)
{
    const auto &tCit = this->tableMap.find(obj.table);
    if (tCit == this->tableMap.cend())
    {
        return false;
    }

    const auto &hCit = this->hashMap.find(obj.hash.value);
    if (hCit == this->hashMap.cend())
    {
        return false;
    }

    auto &table = tCit->second;
    table.incrementRefCount();

    auto &hash = hCit->second;
    hash.incrementRefCount();

    return true;
}

template<>
bool PbhManager::addDependencies(const PbhHash &obj)
{
    std::vector<std::unordered_map<std::string, PbhHashField>::iterator> itList;

    for (const auto &cit : obj.hash_field_list.value)
    {
        const auto &hfCit = this->hashFieldMap.find(cit);
        if (hfCit == this->hashFieldMap.cend())
        {
            return false;
        }

        itList.push_back(hfCit);
    }

    for (auto &it : itList)
    {
        auto &hashField = it->second;
        hashField.incrementRefCount();
    }

    return true;
}

template<>
bool PbhManager::removeDependencies(const PbhRule &obj)
{
    const auto &tCit = this->tableMap.find(obj.table);
    if (tCit == this->tableMap.cend())
    {
        return false;
    }

    const auto &hCit = this->hashMap.find(obj.hash.value);
    if (hCit == this->hashMap.cend())
    {
        return false;
    }

    auto &table = tCit->second;
    table.decrementRefCount();

    auto &hash = hCit->second;
    hash.decrementRefCount();

    return true;
}

template<>
bool PbhManager::removeDependencies(const PbhHash &obj)
{
    std::vector<std::unordered_map<std::string, PbhHashField>::iterator> itList;

    for (const auto &cit : obj.hash_field_list.value)
    {
        const auto &hfCit = this->hashFieldMap.find(cit);
        if (hfCit == this->hashFieldMap.cend())
        {
            return false;
        }

        itList.push_back(hfCit);
    }

    for (auto &it : itList)
    {
        auto &hashField = it->second;
        hashField.decrementRefCount();
    }

    return true;
}

bool PbhManager::getPbhTable(PbhTable &table, const std::string &key) const
{
    const auto &cit = this->tableMap.find(key);
    if (cit == this->tableMap.cend())
    {
        return false;
    }

    table = cit->second;

    return true;
}

bool PbhManager::getPbhRule(PbhRule &rule, const std::string &key) const
{
    const auto &cit = this->ruleMap.find(key);
    if (cit == this->ruleMap.cend())
    {
        return false;
    }

    rule = cit->second;

    return true;
}

bool PbhManager::getPbhHash(PbhHash &hash, const std::string &key) const
{
    const auto &cit = this->hashMap.find(key);
    if (cit == this->hashMap.cend())
    {
        return false;
    }

    hash = cit->second;

    return true;
}

bool PbhManager::getPbhHashField(PbhHashField &hashField, const std::string &key) const
{
    const auto &cit = this->hashFieldMap.find(key);
    if (cit == this->hashFieldMap.cend())
    {
        return false;
    }

    hashField = cit->second;

    return true;
}

bool PbhManager::addPbhTable(const PbhTable &table)
{
    const auto &cit = this->tableMap.find(table.key);
    if (cit != this->tableMap.cend())
    {
        return false;
    }

    this->tableMap[table.key] = table;

    return true;
}

bool PbhManager::updatePbhTable(const PbhTable &table)
{
    const auto &cit = this->tableMap.find(table.key);
    if (cit == this->tableMap.cend())
    {
        return false;
    }

    this->tableMap[table.key] = table;

    return true;
}

bool PbhManager::removePbhTable(const std::string &key)
{
    const auto &cit = this->tableMap.find(key);
    if (cit == this->tableMap.cend())
    {
        return false;
    }

    if (this->tableMap.erase(key) != 1)
    {
        return false;
    }

    return true;
}

bool PbhManager::addPbhRule(const PbhRule &rule)
{
    const auto &cit = this->ruleMap.find(rule.key);
    if (cit != this->ruleMap.cend())
    {
        return false;
    }

    this->ruleMap[rule.key] = rule;

    return true;
}

bool PbhManager::updatePbhRule(const PbhRule &rule)
{
    const auto &cit = this->ruleMap.find(rule.key);
    if (cit == this->ruleMap.cend())
    {
        return false;
    }

    this->ruleMap[rule.key] = rule;

    return true;
}

bool PbhManager::removePbhRule(const std::string &key)
{
    const auto &cit = this->ruleMap.find(key);
    if (cit == this->ruleMap.cend())
    {
        return false;
    }

    if (this->ruleMap.erase(key) != 1)
    {
        return false;
    }

    return true;
}

bool PbhManager::addPbhHash(const PbhHash &hash)
{
    const auto &cit = this->hashMap.find(hash.key);
    if (cit != this->hashMap.cend())
    {
        return false;
    }

    this->hashMap[hash.key] = hash;

    return true;
}

bool PbhManager::updatePbhHash(const PbhHash &hash)
{
    const auto &cit = this->hashMap.find(hash.key);
    if (cit == this->hashMap.cend())
    {
        return false;
    }

    this->hashMap[hash.key] = hash;

    return true;
}

bool PbhManager::removePbhHash(const std::string &key)
{
    const auto &cit = this->hashMap.find(key);
    if (cit == this->hashMap.cend())
    {
        return false;
    }

    if (this->hashMap.erase(key) != 1)
    {
        return false;
    }

    return true;
}

bool PbhManager::addPbhHashField(const PbhHashField &hashField)
{
    const auto &cit = this->hashFieldMap.find(hashField.key);
    if (cit != this->hashFieldMap.cend())
    {
        return false;
    }

    this->hashFieldMap[hashField.key] = hashField;

    return true;
}

bool PbhManager::updatePbhHashField(const PbhHashField &hashField)
{
    const auto &cit = this->hashFieldMap.find(hashField.key);
    if (cit == this->hashFieldMap.cend())
    {
        return false;
    }

    this->hashFieldMap[hashField.key] = hashField;

    return true;
}

bool PbhManager::removePbhHashField(const std::string &key)
{
    const auto &cit = this->hashFieldMap.find(key);
    if (cit == this->hashFieldMap.cend())
    {
        return false;
    }

    if (this->hashFieldMap.erase(key) != 1)
    {
        return false;
    }

    return true;
}

bool PbhManager::parsePbhTableInterfaceList(PbhTable &table, const std::string &field, const std::string &value) const
{
    SWSS_LOG_ENTER();

    const auto &ifList = tokenize(value, ',');

    if (ifList.empty())
    {
        SWSS_LOG_ERROR("Failed to parse field(%s): empty list is prohibited", field.c_str());
        return false;
    }

    table.interface_list.value = std::unordered_set<std::string>(ifList.cbegin(), ifList.cend());
    table.interface_list.is_set = true;

    if (table.interface_list.value.size() != ifList.size())
    {
        SWSS_LOG_WARN("Duplicate interfaces in field(%s): unexpected value(%s)", field.c_str(), value.c_str());
    }

    return true;
}

bool PbhManager::parsePbhTableDescription(PbhTable &table, const std::string &field, const std::string &value) const
{
    SWSS_LOG_ENTER();

    if (value.empty())
    {
        SWSS_LOG_ERROR("Failed to parse field(%s): empty string is prohibited", field.c_str());
        return false;
    }

    table.description.value = value;
    table.description.is_set = true;

    return true;
}

bool PbhManager::parsePbhTable(PbhTable &table) const
{
    SWSS_LOG_ENTER();

    for (const auto &cit : table.fieldValueMap)
    {
        const auto &field = cit.first;
        const auto &value = cit.second;

        if (field == PBH_TABLE_INTERFACE_LIST)
        {
            if (!this->parsePbhTableInterfaceList(table, field, value))
            {
                return false;
            }
        }
        else if (field == PBH_TABLE_DESCRIPTION)
        {
            if (!this->parsePbhTableDescription(table, field, value))
            {
                return false;
            }
        }
        else
        {
            SWSS_LOG_WARN("Unknown field(%s): skipping ...", field.c_str());
        }
    }

    return this->validatePbhTable(table);
}

bool PbhManager::parsePbhRulePriority(PbhRule &rule, const std::string &field, const std::string &value) const
{
    SWSS_LOG_ENTER();

    try
    {
        rule.priority.value = to_uint<sai_uint32_t>(value);
        rule.priority.is_set = true;
    }
    catch (const std::exception &e)
    {
        SWSS_LOG_ERROR("Failed to parse field(%s): %s", field.c_str(), e.what());
        return false;
    }

    return true;
}

bool PbhManager::parsePbhRuleGreKey(PbhRule &rule, const std::string &field, const std::string &value) const
{
    SWSS_LOG_ENTER();

    const auto &vmList = tokenize(value, '/');

    if (vmList.size() != 2)
    {
        SWSS_LOG_ERROR("Failed to parse field(%s): invalid value(%s)", field.c_str(), value.c_str());
        return false;
    }

    try
    {
        rule.gre_key.value = PbhManager::toUInt32(vmList[0]);
        rule.gre_key.mask = PbhManager::toUInt32(vmList[1]);
        rule.gre_key.is_set = true;
    }
    catch (const std::exception &e)
    {
        SWSS_LOG_ERROR("Failed to parse field(%s): %s", field.c_str(), e.what());
        return false;
    }

    return true;
}

bool PbhManager::parsePbhRuleIpProtocol(PbhRule &rule, const std::string &field, const std::string &value) const
{
    SWSS_LOG_ENTER();

    const auto &vmList = tokenize(value, '/');

    if (vmList.size() != 2)
    {
        SWSS_LOG_ERROR("Failed to parse field(%s): invalid value(%s)", field.c_str(), value.c_str());
        return false;
    }

    try
    {
        rule.ip_protocol.value = PbhManager::toUInt8(vmList[0]);
        rule.ip_protocol.mask = PbhManager::toUInt8(vmList[1]);
        rule.ip_protocol.is_set = true;
    }
    catch (const std::exception &e)
    {
        SWSS_LOG_ERROR("Failed to parse field(%s): %s", field.c_str(), e.what());
        return false;
    }

    return true;
}

bool PbhManager::parsePbhRuleIpv6NextHeader(PbhRule &rule, const std::string &field, const std::string &value) const
{
    SWSS_LOG_ENTER();

    const auto &vmList = tokenize(value, '/');

    if (vmList.size() != 2)
    {
        SWSS_LOG_ERROR("Failed to parse field(%s): invalid value(%s)", field.c_str(), value.c_str());
        return false;
    }

    try
    {
        rule.ipv6_next_header.value = PbhManager::toUInt8(vmList[0]);
        rule.ipv6_next_header.mask = PbhManager::toUInt8(vmList[1]);
        rule.ipv6_next_header.is_set = true;
    }
    catch (const std::exception &e)
    {
        SWSS_LOG_ERROR("Failed to parse field(%s): %s", field.c_str(), e.what());
        return false;
    }

    return true;
}

bool PbhManager::parsePbhRuleL4DstPort(PbhRule &rule, const std::string &field, const std::string &value) const
{
    SWSS_LOG_ENTER();

    const auto &vmList = tokenize(value, '/');

    if (vmList.size() != 2)
    {
        SWSS_LOG_ERROR("Failed to parse field(%s): invalid value(%s)", field.c_str(), value.c_str());
        return false;
    }

    try
    {
        rule.l4_dst_port.value = PbhManager::toUInt16(vmList[0]);
        rule.l4_dst_port.mask = PbhManager::toUInt16(vmList[1]);
        rule.l4_dst_port.is_set = true;
    }
    catch (const std::exception &e)
    {
        SWSS_LOG_ERROR("Failed to parse field(%s): %s", field.c_str(), e.what());
        return false;
    }

    return true;
}

bool PbhManager::parsePbhRuleInnerEtherType(PbhRule &rule, const std::string &field, const std::string &value) const
{
    SWSS_LOG_ENTER();

    const auto &vmList = tokenize(value, '/');

    if (vmList.size() != 2)
    {
        SWSS_LOG_ERROR("Failed to parse field(%s): invalid value(%s)", field.c_str(), value.c_str());
        return false;
    }

    try
    {
        rule.inner_ether_type.value = PbhManager::toUInt16(vmList[0]);
        rule.inner_ether_type.mask = PbhManager::toUInt16(vmList[1]);
        rule.inner_ether_type.is_set = true;
    }
    catch (const std::exception &e)
    {
        SWSS_LOG_ERROR("Failed to parse field(%s): %s", field.c_str(), e.what());
        return false;
    }

    return true;
}

bool PbhManager::parsePbhRuleHash(PbhRule &rule, const std::string &field, const std::string &value) const
{
    SWSS_LOG_ENTER();

    if (value.empty())
    {
        SWSS_LOG_ERROR("Failed to parse field(%s): empty value is prohibited", field.c_str());
        return false;
    }

    rule.hash.value = value;
    rule.hash.is_set = true;

    return true;
}

bool PbhManager::parsePbhRulePacketAction(PbhRule &rule, const std::string &field, const std::string &value) const
{
    SWSS_LOG_ENTER();

    const auto &cit = pbhRulePacketActionMap.find(value);
    if (cit == pbhRulePacketActionMap.cend())
    {
        SWSS_LOG_ERROR("Failed to parse field(%s): invalid value(%s)", field.c_str(), value.c_str());
        return false;
    }

    rule.packet_action.value = pbhRulePacketActionMap.at(value);
    rule.packet_action.is_set = true;

    return true;
}

bool PbhManager::parsePbhRuleFlowCounter(PbhRule &rule, const std::string &field, const std::string &value) const
{
    SWSS_LOG_ENTER();

    const auto &cit = pbhRuleFlowCounterMap.find(value);
    if (cit == pbhRuleFlowCounterMap.cend())
    {
        SWSS_LOG_ERROR("Failed to parse field(%s): invalid value(%s)", field.c_str(), value.c_str());
        return false;
    }

    rule.flow_counter.name = field;
    rule.flow_counter.value = pbhRuleFlowCounterMap.at(value);
    rule.flow_counter.is_set = true;

    return true;
}

bool PbhManager::parsePbhRule(PbhRule &rule) const
{
    SWSS_LOG_ENTER();

    for (const auto &cit : rule.fieldValueMap)
    {
        const auto &field = cit.first;
        const auto &value = cit.second;

        if (field == PBH_RULE_PRIORITY)
        {
            if (!this->parsePbhRulePriority(rule, field, value))
            {
                return false;
            }
        }
        else if (field == PBH_RULE_GRE_KEY)
        {
            if (!this->parsePbhRuleGreKey(rule, field, value))
            {
                return false;
            }
        }
        else if (field == PBH_RULE_IP_PROTOCOL)
        {
            if (!this->parsePbhRuleIpProtocol(rule, field, value))
            {
                return false;
            }
        }
        else if (field == PBH_RULE_IPV6_NEXT_HEADER)
        {
            if (!this->parsePbhRuleIpv6NextHeader(rule, field, value))
            {
                return false;
            }
        }
        else if (field == PBH_RULE_L4_DST_PORT)
        {
            if (!this->parsePbhRuleL4DstPort(rule, field, value))
            {
                return false;
            }
        }
        else if (field == PBH_RULE_INNER_ETHER_TYPE)
        {
            if (!this->parsePbhRuleInnerEtherType(rule, field, value))
            {
                return false;
            }
        }
        else if (field == PBH_RULE_HASH)
        {
            if (!this->parsePbhRuleHash(rule, field, value))
            {
                return false;
            }
        }
        else if (field == PBH_RULE_PACKET_ACTION)
        {
            if (!this->parsePbhRulePacketAction(rule, field, value))
            {
                return false;
            }
        }
        else if (field == PBH_RULE_FLOW_COUNTER)
        {
            if (!this->parsePbhRuleFlowCounter(rule, field, value))
            {
                return false;
            }
        }
        else
        {
            SWSS_LOG_WARN("Unknown field(%s): skipping ...", field.c_str());
        }
    }

    return this->validatePbhRule(rule);
}

bool PbhManager::parsePbhHashHashFieldList(PbhHash &hash, const std::string &field, const std::string &value) const
{
    SWSS_LOG_ENTER();

    const auto &hfList = tokenize(value, ',');

    if (hfList.empty())
    {
        SWSS_LOG_ERROR("Failed to parse field(%s): empty list is prohibited", field.c_str());
        return false;
    }

    hash.hash_field_list.value = std::unordered_set<std::string>(hfList.cbegin(), hfList.cend());
    hash.hash_field_list.is_set = true;

    if (hash.hash_field_list.value.size() != hfList.size())
    {
        SWSS_LOG_WARN("Duplicate hash fields in field(%s): unexpected value(%s)", field.c_str(), value.c_str());
    }

    return true;
}

bool PbhManager::parsePbhHash(PbhHash &hash) const
{
    SWSS_LOG_ENTER();

    for (const auto &cit : hash.fieldValueMap)
    {
        const auto &field = cit.first;
        const auto &value = cit.second;

        if (field == PBH_HASH_HASH_FIELD_LIST)
        {
            if (!this->parsePbhHashHashFieldList(hash, field, value))
            {
                return false;
            }
        }
        else
        {
            SWSS_LOG_WARN("Unknown field(%s): skipping ...", field.c_str());
        }
    }

    return this->validatePbhHash(hash);
}

bool PbhManager::parsePbhHashFieldHashField(PbhHashField &hashField, const std::string &field, const std::string &value) const
{
    SWSS_LOG_ENTER();

    const auto &cit = pbhHashFieldHashFieldMap.find(value);
    if (cit == pbhHashFieldHashFieldMap.cend())
    {
        SWSS_LOG_ERROR("Failed to parse field(%s): invalid value(%s)", field.c_str(), value.c_str());
        return false;
    }

    hashField.hash_field.value = pbhHashFieldHashFieldMap.at(value);
    hashField.hash_field.is_set = true;

    return true;
}

bool PbhManager::parsePbhHashFieldIpMask(PbhHashField &hashField, const std::string &field, const std::string &value) const
{
    SWSS_LOG_ENTER();

    try
    {
        hashField.ip_mask.value = IpAddress(value);
        hashField.ip_mask.is_set = true;
    }
    catch (const std::exception &e)
    {
        SWSS_LOG_ERROR("Failed to parse field(%s): %s", field.c_str(), e.what());
        return false;
    }

    return true;
}

bool PbhManager::parsePbhHashFieldSequenceId(PbhHashField &hashField, const std::string &field, const std::string &value) const
{
    SWSS_LOG_ENTER();

    try
    {
        hashField.sequence_id.value = to_uint<sai_uint32_t>(value);
        hashField.sequence_id.is_set = true;
    }
    catch (const std::exception &e)
    {
        SWSS_LOG_ERROR("Failed to parse field(%s): %s", field.c_str(), e.what());
        return false;
    }

    return true;
}

bool PbhManager::parsePbhHashField(PbhHashField &hashField) const
{
    SWSS_LOG_ENTER();

    for (const auto &cit : hashField.fieldValueMap)
    {
        const auto &field = cit.first;
        const auto &value = cit.second;

        if (field == PBH_HASH_FIELD_HASH_FIELD)
        {
            if (!this->parsePbhHashFieldHashField(hashField, field, value))
            {
                return false;
            }
        }
        else if (field == PBH_HASH_FIELD_IP_MASK)
        {
            if (!this->parsePbhHashFieldIpMask(hashField, field, value))
            {
                return false;
            }
        }
        else if (field == PBH_HASH_FIELD_SEQUENCE_ID)
        {
            if (!this->parsePbhHashFieldSequenceId(hashField, field, value))
            {
                return false;
            }
        }
        else
        {
            SWSS_LOG_WARN("Unknown field(%s): skipping ...", field.c_str());
        }
    }

    return this->validatePbhHashField(hashField);
}

bool PbhManager::validatePbhTable(PbhTable &table) const
{
    SWSS_LOG_ENTER();

    if (!table.interface_list.is_set)
    {
        SWSS_LOG_ERROR("Validation error: missing mandatory field(%s)", PBH_TABLE_INTERFACE_LIST);
        return false;
    }

    if (!table.description.is_set)
    {
        SWSS_LOG_ERROR("Validation error: missing mandatory field(%s)", PBH_TABLE_DESCRIPTION);
        return false;
    }

    return true;
}

bool PbhManager::validatePbhRule(PbhRule &rule) const
{
    SWSS_LOG_ENTER();

    if (!rule.priority.is_set)
    {
        SWSS_LOG_ERROR("Validation error: missing mandatory field(%s)", PBH_RULE_PRIORITY);
        return false;
    }

    if (!rule.hash.is_set)
    {
        SWSS_LOG_ERROR("Validation error: missing mandatory field(%s)", PBH_RULE_HASH);
        return false;
    }

    if (!rule.packet_action.is_set)
    {
        SWSS_LOG_NOTICE(
            "Missing non mandatory field(%s): setting default value(%s)",
            PBH_RULE_PACKET_ACTION,
            PBH_RULE_PACKET_ACTION_SET_ECMP_HASH
        );
        rule.packet_action.value = SAI_ACL_ENTRY_ATTR_ACTION_SET_ECMP_HASH_ID;
        rule.packet_action.is_set = true;
    }

    if (!rule.flow_counter.is_set)
    {
        SWSS_LOG_NOTICE(
            "Missing non mandatory field(%s): setting default value(%s)",
            PBH_RULE_FLOW_COUNTER,
            PBH_RULE_FLOW_COUNTER_DISABLED
        );
        rule.flow_counter.name = PBH_RULE_FLOW_COUNTER;
        rule.flow_counter.value = false;
        rule.flow_counter.is_set = true;
    }

    return true;
}

bool PbhManager::validatePbhHash(PbhHash &hash) const
{
    SWSS_LOG_ENTER();

    if (!hash.hash_field_list.is_set)
    {
        SWSS_LOG_ERROR("Validation error: missing mandatory field(%s)", PBH_HASH_HASH_FIELD_LIST);
        return false;
    }

    return true;
}

bool PbhManager::validatePbhHashField(PbhHashField &hashField) const
{
    SWSS_LOG_ENTER();

    if (!hashField.hash_field.is_set)
    {
        SWSS_LOG_ERROR("Validation error: missing mandatory field(%s)", PBH_HASH_FIELD_HASH_FIELD);
        return false;
    }

    if (hashField.ip_mask.is_set)
    {
        if (hashField.ip_mask.value.isV4())
        {
            if (!this->isIpv4MaskRequired(hashField.hash_field.value))
            {
                SWSS_LOG_ERROR("Validation error: field(%s) is prohibited", PBH_HASH_FIELD_IP_MASK);
                return false;
            }
        }
        else
        {
            if (!this->isIpv6MaskRequired(hashField.hash_field.value))
            {
                SWSS_LOG_ERROR("Validation error: field(%s) is prohibited", PBH_HASH_FIELD_IP_MASK);
                return false;
            }
        }
    }

    if (!hashField.sequence_id.is_set)
    {
        SWSS_LOG_ERROR("Validation error: missing mandatory field(%s)", PBH_HASH_FIELD_SEQUENCE_ID);
        return false;
    }

    return true;
}

bool PbhManager::isIpv4MaskRequired(const sai_native_hash_field_t &value) const
{
    switch (value)
    {
        case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV4:
        case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV4:
            return true;

        default:
            break;
    }

    return false;
}

bool PbhManager::isIpv6MaskRequired(const sai_native_hash_field_t &value) const
{
    switch (value)
    {
        case SAI_NATIVE_HASH_FIELD_INNER_DST_IPV6:
        case SAI_NATIVE_HASH_FIELD_INNER_SRC_IPV6:
            return true;

        default:
            break;
    }

    return false;
}
