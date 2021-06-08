// includes -----------------------------------------------------------------------------------------------------------

#include <cstring>

#include <algorithm>
#include <iterator>
#include <utility>
#include <memory>
#include <string>
#include <vector>
#include <set>

#include "pbhorch.h"

template<typename K, typename V>
using umap_t = std::unordered_map<K, V>;

using namespace swss;

// variables ----------------------------------------------------------------------------------------------------------

extern sai_hash_api_t *sai_hash_api;
extern sai_object_id_t gSwitchId;

// helpers ------------------------------------------------------------------------------------------------------------

template<typename K, typename V>
static inline std::set<K> uMapToKeySet(const umap_t<K, V> &uMap)
{
    std::set<K> s;

    std::transform(
        uMap.cbegin(),
        uMap.cend(),
        std::inserter(s, s.begin()),
        [](const std::pair<K, V> &p) {
            return p.first;
        }
    );

    return s;
}

template<typename K, typename V>
static inline std::vector<K> uMapDiffByKey(const umap_t<K, V> &uMap1, const umap_t<K, V> &uMap2)
{
    std::vector<K> v;

    const auto &s1 = uMapToKeySet(uMap1);
    const auto &s2 = uMapToKeySet(uMap2);

    std::set_symmetric_difference(
        s1.cbegin(),
        s1.cend(),
        s2.cbegin(),
        s2.cend(),
        std::back_inserter(v)
    );

    return v;
}

// PBH OA -------------------------------------------------------------------------------------------------------------

PbhOrch::PbhOrch(
    std::vector<TableConnector> &connectorList,
    AclOrch *aclOrch,
    PortsOrch *portsOrch
) : Orch(connectorList)
{
    this->aclOrch = aclOrch;
    this->portsOrch = portsOrch;
}

PbhOrch::~PbhOrch()
{

}

// PBH table ----------------------------------------------------------------------------------------------------------

bool PbhOrch::createPbhTable(const PbhTable &table)
{
    SWSS_LOG_ENTER();

    PbhTable tObj;

    if (this->pbhMgr.getPbhTable(tObj, table.key))
    {
        SWSS_LOG_ERROR("Failed to create PBH table(%s) in HW: object already exists", table.key.c_str());
        return false;
    }

    AclTable pbhTable(this->aclOrch, table.name);

    if (!pbhTable.validateAddType(acl_table_type_t::ACL_TABLE_PBH))
    {
        SWSS_LOG_ERROR("Failed to configure PBH table(%s) type", table.key.c_str());
        return false;
    }

    if (!pbhTable.validateAddStage(acl_stage_type_t::ACL_STAGE_INGRESS))
    {
        SWSS_LOG_ERROR("Failed to configure PBH table(%s) stage", table.key.c_str());
        return false;
    }

    if (table.interface_list.is_set)
    {
        if (!pbhTable.validateAddPorts(table.interface_list.value))
        {
            SWSS_LOG_ERROR("Failed to configure PBH table(%s) ports", table.key.c_str());
            return false;
        }
    }

    if (table.description.is_set)
    {
        pbhTable.setDescription(table.description.value);
    }

    if (!pbhTable.validate())
    {
        SWSS_LOG_ERROR("Failed to validate PBH table(%s)", table.key.c_str());
        return false;
    }

    if (!this->aclOrch->addAclTable(pbhTable))
    {
        SWSS_LOG_ERROR("Failed to create PBH table(%s) in HW", table.key.c_str());
        return false;
    }

    if (!this->pbhMgr.addPbhTable(table))
    {
        SWSS_LOG_ERROR("Failed to add PBH table(%s) to internal cache", table.key.c_str());
        return false;
    }

    SWSS_LOG_NOTICE("Created PBH table(%s) in HW", table.key.c_str());

    return true;
}

bool PbhOrch::updatePbhTable(const PbhTable &table)
{
    SWSS_LOG_ENTER();

    PbhTable tObj;

    if (!this->pbhMgr.getPbhTable(tObj, table.key))
    {
        SWSS_LOG_ERROR("Failed to update PBH table(%s) in HW: object doesn't exist", table.key.c_str());
        return false;
    }

    AclTable pbhTable(this->aclOrch, table.name);

    if (table.interface_list.is_set)
    {
        if (!pbhTable.validateAddPorts(table.interface_list.value))
        {
            SWSS_LOG_ERROR("Failed to configure PBH table(%s) ports", table.key.c_str());
            return false;
        }
    }

    if (table.description.is_set)
    {
        pbhTable.setDescription(table.description.value);
    }

    if (!this->aclOrch->updateAclTable(table.name, pbhTable))
    {
        SWSS_LOG_ERROR("Failed to update PBH table(%s) in HW", table.key.c_str());
        return false;
    }

    if (!this->pbhMgr.updatePbhTable(table))
    {
        SWSS_LOG_ERROR("Failed to update PBH table(%s) in internal cache", table.key.c_str());
        return false;
    }

    SWSS_LOG_NOTICE("Updated PBH table(%s) in HW", table.key.c_str());

    return true;
}

bool PbhOrch::removePbhTable(const PbhTable &table)
{
    SWSS_LOG_ENTER();

    PbhTable tObj;

    if (!this->pbhMgr.getPbhTable(tObj, table.key))
    {
        SWSS_LOG_ERROR("Failed to remove PBH table(%s) from HW: object doesn't exist", table.key.c_str());
        return false;
    }

    if (!this->aclOrch->removeAclTable(table.name))
    {
        SWSS_LOG_ERROR("Failed to remove PBH table(%s) from HW", table.key.c_str());
        return false;
    }

    if (!this->pbhMgr.removePbhTable(table.key))
    {
        SWSS_LOG_ERROR("Failed to remove PBH table(%s) from internal cache", table.key.c_str());
        return false;
    }

    SWSS_LOG_NOTICE("Removed PBH table(%s) from HW", table.key.c_str());

    return true;
}

void PbhOrch::deployPbhTableSetupTasks()
{
    SWSS_LOG_ENTER();

    auto &map = this->pbhMgr.tableTask.pendingSetupMap;
    auto it = map.begin();

    while (it != map.end())
    {
        auto &key = it->first;
        auto &table = it->second;

        PbhTable tObj;

        if (!this->pbhMgr.getPbhTable(tObj, key))
        {
            if (!this->createPbhTable(table))
            {
                SWSS_LOG_ERROR("Failed to create PBH table(%s): ASIC and CONFIG DB are diverged", key.c_str());
            }
            else
            {
                SWSS_LOG_NOTICE("Created PBH table(%s)", key.c_str());
            }
        }
        else
        {
            if (!this->updatePbhTable(table))
            {
                SWSS_LOG_ERROR("Failed to update PBH table(%s): ASIC and CONFIG DB are diverged", key.c_str());
            }
            else
            {
                SWSS_LOG_NOTICE("Updated PBH table(%s)", key.c_str());
            }
        }

        it = map.erase(it);
    }
}

void PbhOrch::deployPbhTableRemoveTasks()
{
    SWSS_LOG_ENTER();

    auto &map = this->pbhMgr.tableTask.pendingRemoveMap;
    auto it = map.begin();

    while (it != map.end())
    {
        auto &key = it->first;
        auto &table = it->second;

        PbhTable tObj;

        if (!this->pbhMgr.getPbhTable(tObj, key))
        {
            SWSS_LOG_ERROR("Failed to remove PBH table(%s): object doesn't exist", key.c_str());
            it = map.erase(it);
            continue;
        }

        if (this->pbhMgr.hasDependencies(tObj))
        {
            SWSS_LOG_WARN("Unable to remove PBH table(%s): object has dependencies: adding retry", key.c_str());
            it++;
            continue;
        }

        if (!this->removePbhTable(table))
        {
            SWSS_LOG_ERROR("Failed to remove PBH table(%s): ASIC and CONFIG DB are diverged", key.c_str());
            it = map.erase(it);
            continue;
        }

        SWSS_LOG_NOTICE("Removed PBH table(%s)", key.c_str());

        it = map.erase(it);
    }
}

// PBH rule -----------------------------------------------------------------------------------------------------------

bool PbhOrch::createPbhRule(const PbhRule &rule)
{
    SWSS_LOG_ENTER();

    PbhRule rObj;

    if (this->pbhMgr.getPbhRule(rObj, rule.key))
    {
        SWSS_LOG_ERROR("Failed to create PBH rule(%s) in HW: object already exists", rule.key.c_str());
        return false;
    }

    std::shared_ptr<AclRulePbh> pbhRule;

    if (rule.flow_counter.is_set)
    {
        pbhRule = std::make_shared<AclRulePbh>(this->aclOrch, rule.name, rule.table, rule.flow_counter.value);
    }
    else
    {
        pbhRule = std::make_shared<AclRulePbh>(this->aclOrch, rule.name, rule.table);
    }

    if (rule.priority.is_set)
    {
        if (!pbhRule->validateAddPriority(rule.priority.value))
        {
            SWSS_LOG_ERROR("Failed to configure PBH rule(%s) priority", rule.key.c_str());
            return false;
        }
    }

    if (rule.gre_key.is_set)
    {
        sai_attribute_t attr;

        attr.id = SAI_ACL_ENTRY_ATTR_FIELD_GRE_KEY;
        attr.value.aclfield.enable = true;
        attr.value.aclfield.data.u32 = rule.gre_key.value;
        attr.value.aclfield.mask.u32 = rule.gre_key.mask;

        if (!pbhRule->validateAddMatch(attr))
        {
            SWSS_LOG_ERROR("Failed to configure PBH rule(%s) match: GRE_KEY", rule.key.c_str());
            return false;
        }
    }

    if (rule.ip_protocol.is_set)
    {
        sai_attribute_t attr;

        attr.id = SAI_ACL_ENTRY_ATTR_FIELD_IP_PROTOCOL;
        attr.value.aclfield.enable = true;
        attr.value.aclfield.data.u8 = rule.ip_protocol.value;
        attr.value.aclfield.mask.u8 = rule.ip_protocol.mask;

        if (!pbhRule->validateAddMatch(attr))
        {
            SWSS_LOG_ERROR("Failed to configure PBH rule(%s) match: IP_PROTOCOL", rule.key.c_str());
            return false;
        }
    }

    if (rule.ipv6_next_header.is_set)
    {
        sai_attribute_t attr;

        attr.id = SAI_ACL_ENTRY_ATTR_FIELD_IPV6_NEXT_HEADER;
        attr.value.aclfield.enable = true;
        attr.value.aclfield.data.u8 = rule.ipv6_next_header.value;
        attr.value.aclfield.mask.u8 = rule.ipv6_next_header.mask;

        if (!pbhRule->validateAddMatch(attr))
        {
            SWSS_LOG_ERROR("Failed to configure PBH rule(%s) match: IPV6_NEXT_HEADER", rule.key.c_str());
            return false;
        }
    }

    if (rule.l4_dst_port.is_set)
    {
        sai_attribute_t attr;

        attr.id = SAI_ACL_ENTRY_ATTR_FIELD_L4_DST_PORT;
        attr.value.aclfield.enable = true;
        attr.value.aclfield.data.u16 = rule.l4_dst_port.value;
        attr.value.aclfield.mask.u16 = rule.l4_dst_port.mask;

        if (!pbhRule->validateAddMatch(attr))
        {
            SWSS_LOG_ERROR("Failed to configure PBH rule(%s) match: L4_DST_PORT", rule.key.c_str());
            return false;
        }
    }

    if (rule.inner_ether_type.is_set)
    {
        sai_attribute_t attr;

        attr.id = SAI_ACL_ENTRY_ATTR_FIELD_INNER_ETHER_TYPE;
        attr.value.aclfield.enable = true;
        attr.value.aclfield.data.u16 = rule.inner_ether_type.value;
        attr.value.aclfield.mask.u16 = rule.inner_ether_type.mask;

        if (!pbhRule->validateAddMatch(attr))
        {
            SWSS_LOG_ERROR("Failed to configure PBH rule(%s) match: INNER_ETHER_TYPE", rule.key.c_str());
            return false;
        }
    }

    if (rule.hash.is_set && rule.packet_action.is_set)
    {
        PbhHash hObj;

        if (this->pbhMgr.getPbhHash(hObj, rule.hash.value))
        {
            sai_attribute_t attr;

            attr.id = rule.packet_action.value;
            attr.value.aclaction.enable = true;
            attr.value.aclaction.parameter.oid = hObj.getOid();

            if (!pbhRule->validateAddAction(attr))
            {
                SWSS_LOG_ERROR("Failed to configure PBH rule(%s) action", rule.key.c_str());
                return false;
            }
        }
    }

    if (!pbhRule->validate())
    {
        SWSS_LOG_ERROR("Failed to validate PBH rule(%s)", rule.key.c_str());
        return false;
    }

    if (!this->aclOrch->addAclRule(pbhRule, rule.table))
    {
        SWSS_LOG_ERROR("Failed to create PBH rule(%s) in HW", rule.key.c_str());
        return false;
    }

    if (!this->pbhMgr.addPbhRule(rule))
    {
        SWSS_LOG_ERROR("Failed to add PBH rule(%s) to internal cache", rule.key.c_str());
        return false;
    }

    if (!this->pbhMgr.addDependencies(rule))
    {
        SWSS_LOG_ERROR("Failed to add PBH rule(%s) dependencies", rule.key.c_str());
        return false;
    }

    SWSS_LOG_NOTICE("Created PBH rule(%s) in HW", rule.key.c_str());

    return true;
}

bool PbhOrch::updatePbhRule(const PbhRule &rule)
{
    SWSS_LOG_ENTER();

    PbhRule rObj;

    if (!this->pbhMgr.getPbhRule(rObj, rule.key))
    {
        SWSS_LOG_ERROR("Failed to update PBH rule(%s) in HW: object doesn't exist", rule.key.c_str());
        return false;
    }

    if (!uMapDiffByKey(rObj.fieldValueMap, rule.fieldValueMap).empty())
    {
        SWSS_LOG_ERROR("Failed to update PBH rule(%s) in HW: fields add/remove is prohibited", rule.key.c_str());
        return false;
    }

    bool flowCounterUpdate = false;

    for (const auto &oCit : rObj.fieldValueMap)
    {
        const auto &field = oCit.first;

        const auto &oValue = oCit.second;
        const auto &nValue = rule.fieldValueMap.at(field);

        if (oValue == nValue)
        {
            continue;
        }

        if (field != rule.flow_counter.name)
        {
            SWSS_LOG_ERROR(
                "Failed to update PBH rule(%s) in HW: field(%s) update is prohibited",
                rule.key.c_str(),
                field.c_str()
            );
            return false;
        }

        flowCounterUpdate = true;
    }

    if (!flowCounterUpdate)
    {
        SWSS_LOG_NOTICE("PBH rule(%s) in HW is up-to-date", rule.key.c_str());
        return true;
    }

    if (!this->aclOrch->updateAclRule(rule.table, rule.name, rule.flow_counter.value))
    {
        SWSS_LOG_ERROR("Failed to update PBH rule(%s) in HW", rule.key.c_str());
        return false;
    }

    if (!this->pbhMgr.updatePbhRule(rule))
    {
        SWSS_LOG_ERROR("Failed to update PBH rule(%s) in internal cache", rule.key.c_str());
        return false;
    }

    SWSS_LOG_NOTICE("Updated PBH rule(%s) in HW", rule.key.c_str());

    return true;
}

bool PbhOrch::removePbhRule(const PbhRule &rule)
{
    SWSS_LOG_ENTER();

    PbhRule rObj;

    if (!this->pbhMgr.getPbhRule(rObj, rule.key))
    {
        SWSS_LOG_ERROR("Failed to remove PBH rule(%s) from HW: object doesn't exist", rule.key.c_str());
        return false;
    }

    if (!this->aclOrch->removeAclRule(rObj.table, rObj.name))
    {
        SWSS_LOG_ERROR("Failed to remove PBH rule(%s) from HW", rObj.key.c_str());
        return false;
    }

    if (!this->pbhMgr.removePbhRule(rObj.key))
    {
        SWSS_LOG_ERROR("Failed to remove PBH rule(%s) from internal cache", rObj.key.c_str());
        return false;
    }

    if (!this->pbhMgr.removeDependencies(rObj))
    {
        SWSS_LOG_ERROR("Failed to remove PBH rule(%s) dependencies", rObj.key.c_str());
        return false;
    }

    SWSS_LOG_NOTICE("Removed PBH rule(%s) from HW", rObj.key.c_str());

    return true;
}

void PbhOrch::deployPbhRuleSetupTasks()
{
    SWSS_LOG_ENTER();

    auto &map = this->pbhMgr.ruleTask.pendingSetupMap;
    auto it = map.begin();

    while (it != map.end())
    {
        auto &key = it->first;
        auto &rule = it->second;

        if (!this->pbhMgr.validateDependencies(rule))
        {
            SWSS_LOG_WARN("Unable to setup PBH rule(%s): object has missing dependencies: adding retry", key.c_str());
            it++;
            continue;
        }

        PbhRule rObj;

        if (!this->pbhMgr.getPbhRule(rObj, key))
        {
            if (!this->createPbhRule(rule))
            {
                SWSS_LOG_ERROR("Failed to create PBH rule(%s): ASIC and CONFIG DB are diverged", key.c_str());
            }
            else
            {
                SWSS_LOG_NOTICE("Created PBH rule(%s)", key.c_str());
            }
        }
        else
        {
            if (!this->updatePbhRule(rule))
            {
                SWSS_LOG_ERROR("Failed to update PBH rule(%s): ASIC and CONFIG DB are diverged", key.c_str());
            }
            else
            {
                SWSS_LOG_NOTICE("Updated PBH rule(%s)", key.c_str());
            }
        }

        it = map.erase(it);
    }
}

void PbhOrch::deployPbhRuleRemoveTasks()
{
    SWSS_LOG_ENTER();

    auto &map = this->pbhMgr.ruleTask.pendingRemoveMap;
    auto it = map.begin();

    while (it != map.end())
    {
        auto &key = it->first;
        auto &rule = it->second;

        PbhRule rObj;

        if (!this->pbhMgr.getPbhRule(rObj, key))
        {
            SWSS_LOG_ERROR("Failed to remove PBH rule(%s): object doesn't exist", key.c_str());
            it = map.erase(it);
            continue;
        }

        if (!this->removePbhRule(rule))
        {
            SWSS_LOG_ERROR("Failed to remove PBH rule(%s): ASIC and CONFIG DB are diverged", key.c_str());
            it = map.erase(it);
            continue;
        }

        SWSS_LOG_NOTICE("Removed PBH rule(%s)", key.c_str());

        it = map.erase(it);
    }
}

// PBH hash -----------------------------------------------------------------------------------------------------------

bool PbhOrch::createPbhHash(const PbhHash &hash)
{
    SWSS_LOG_ENTER();

    PbhHash hObj;

    if (this->pbhMgr.getPbhHash(hObj, hash.key))
    {
        SWSS_LOG_ERROR("Failed to create PBH hash(%s) in HW: object already exists", hash.key.c_str());
        return false;
    }

    std::vector<sai_object_id_t> hashFieldOidList;

    if (hash.hash_field_list.is_set)
    {
        for (const auto &cit : hash.hash_field_list.value)
        {
            PbhHashField hfObj;

            if (!this->pbhMgr.getPbhHashField(hfObj, cit))
            {
                SWSS_LOG_ERROR(
                    "Failed to create PBH hash(%s) in HW: missing hash field(%s)",
                    hash.key.c_str(),
                    cit.c_str()
                );
                return false;
            }

            hashFieldOidList.push_back(hfObj.getOid());
        }
    }

    if (hashFieldOidList.empty())
    {
        SWSS_LOG_ERROR("Failed to create PBH hash(%s) in HW: missing hash fields", hash.key.c_str());
        return false;
    }

    sai_attribute_t attr;
    std::vector<sai_attribute_t> attrList;

    attr.id = SAI_HASH_ATTR_FINE_GRAINED_HASH_FIELD_LIST;
    attr.value.objlist.count = static_cast<sai_uint32_t>(hashFieldOidList.size());
    attr.value.objlist.list = hashFieldOidList.data();
    attrList.push_back(attr);

    sai_status_t status;
    sai_object_id_t hashOid;

    status = sai_hash_api->create_hash(&hashOid, gSwitchId, static_cast<sai_uint32_t>(attrList.size()), attrList.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create PBH hash(%s) in HW", hash.key.c_str());
        return false;
    }

    hObj = hash;
    hObj.setOid(hashOid);

    if (!this->pbhMgr.addPbhHash(hObj))
    {
        SWSS_LOG_ERROR("Failed to add PBH hash(%s) to internal cache", hObj.key.c_str());
        return false;
    }

    if (!this->pbhMgr.addDependencies(hObj))
    {
        SWSS_LOG_ERROR("Failed to add PBH hash(%s) dependencies", hObj.key.c_str());
        return false;
    }

    SWSS_LOG_NOTICE("Created PBH hash(%s) in HW", hObj.key.c_str());

    return true;
}

bool PbhOrch::updatePbhHash(const PbhHash &hash)
{
    SWSS_LOG_ENTER();

    PbhHash hObj;

    if (!this->pbhMgr.getPbhHash(hObj, hash.key))
    {
        SWSS_LOG_ERROR("Failed to update PBH hash(%s) in HW: object doesn't exist", hash.key.c_str());
        return false;
    }

    SWSS_LOG_ERROR("Failed to update PBH hash(%s) in HW: operation is prohibited", hash.key.c_str());

    return false;
}

bool PbhOrch::removePbhHash(const PbhHash &hash)
{
    SWSS_LOG_ENTER();

    PbhHash hObj;

    if (!this->pbhMgr.getPbhHash(hObj, hash.key))
    {
        SWSS_LOG_ERROR("Failed to remove PBH hash(%s) from HW: object doesn't exist", hash.key.c_str());
        return false;
    }

    sai_status_t status;

    status = sai_hash_api->remove_hash(hObj.getOid());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to remove PBH hash(%s) from HW", hObj.key.c_str());
        return false;
    }

    if (!this->pbhMgr.removePbhHash(hObj.key))
    {
        SWSS_LOG_ERROR("Failed to remove PBH hash(%s) from internal cache", hObj.key.c_str());
        return false;
    }

    if (!this->pbhMgr.removeDependencies(hObj))
    {
        SWSS_LOG_ERROR("Failed to remove PBH hash(%s) dependencies", hObj.key.c_str());
        return false;
    }

    SWSS_LOG_NOTICE("Removed PBH hash(%s) from HW", hObj.key.c_str());

    return true;
}

void PbhOrch::deployPbhHashSetupTasks()
{
    SWSS_LOG_ENTER();

    auto &map = this->pbhMgr.hashTask.pendingSetupMap;
    auto it = map.begin();

    while (it != map.end())
    {
        auto &key = it->first;
        auto &hash = it->second;

        if (!this->pbhMgr.validateDependencies(hash))
        {
            SWSS_LOG_WARN("Unable to create PBH hash(%s): object has missing dependencies: adding retry", key.c_str());
            it++;
            continue;
        }

        PbhHash hObj;

        if (!this->pbhMgr.getPbhHash(hObj, key))
        {
            if (!this->createPbhHash(hash))
            {
                SWSS_LOG_ERROR("Failed to create PBH hash(%s): ASIC and CONFIG DB are diverged", key.c_str());
            }
            else
            {
                SWSS_LOG_NOTICE("Created PBH hash(%s)", key.c_str());
            }
        }
        else
        {
            if (!this->updatePbhHash(hash))
            {
                SWSS_LOG_ERROR("Failed to update PBH hash(%s): ASIC and CONFIG DB are diverged", key.c_str());
            }
            else
            {
                SWSS_LOG_NOTICE("Updated PBH hash(%s)", key.c_str());
            }
        }

        it = map.erase(it);
    }
}

void PbhOrch::deployPbhHashRemoveTasks()
{
    SWSS_LOG_ENTER();

    auto &map = this->pbhMgr.hashTask.pendingRemoveMap;
    auto it = map.begin();

    while (it != map.end())
    {
        auto &key = it->first;
        auto &hash = it->second;

        PbhHash hObj;

        if (!this->pbhMgr.getPbhHash(hObj, key))
        {
            SWSS_LOG_ERROR("Failed to remove PBH hash(%s): object doesn't exist", key.c_str());
            it = map.erase(it);
            continue;
        }

        if (this->pbhMgr.hasDependencies(hObj))
        {
            SWSS_LOG_WARN("Unable to remove PBH hash(%s): object has dependencies: adding retry", key.c_str());
            it++;
            continue;
        }

        if (!this->removePbhHash(hash))
        {
            SWSS_LOG_ERROR("Failed to remove PBH hash(%s): ASIC and CONFIG DB are diverged", key.c_str());
            it = map.erase(it);
            continue;
        }

        SWSS_LOG_NOTICE("Removed PBH hash(%s)", key.c_str());

        it = map.erase(it);
    }
}

// PBH hash field -----------------------------------------------------------------------------------------------------

bool PbhOrch::createPbhHashField(const PbhHashField &hashField)
{
    SWSS_LOG_ENTER();

    PbhHashField hfObj;

    if (this->pbhMgr.getPbhHashField(hfObj, hashField.key))
    {
        SWSS_LOG_ERROR("Failed to create PBH hash field(%s) in HW: object already exists", hashField.key.c_str());
        return false;
    }

    std::vector<sai_attribute_t> attrList;

    if (hashField.hash_field.is_set)
    {
        sai_attribute_t attr;

        attr.id = SAI_FINE_GRAINED_HASH_FIELD_ATTR_NATIVE_HASH_FIELD;
        attr.value.s32 = hashField.hash_field.value;

        attrList.push_back(attr);
    }

    if (hashField.ip_mask.is_set)
    {
        sai_attribute_t attr;

        if (hashField.ip_mask.value.isV4())
        {
            attr.id = SAI_FINE_GRAINED_HASH_FIELD_ATTR_IPV4_MASK;
            attr.value.ip4 = hashField.ip_mask.value.getV4Addr();
        }
        else
        {
            attr.id = SAI_FINE_GRAINED_HASH_FIELD_ATTR_IPV6_MASK;
            std::memcpy(attr.value.ip6, hashField.ip_mask.value.getV6Addr(), sizeof(attr.value.ip6));
        }

        attrList.push_back(attr);
    }

    if (hashField.sequence_id.is_set)
    {
        sai_attribute_t attr;

        attr.id = SAI_FINE_GRAINED_HASH_FIELD_ATTR_SEQUENCE_ID;
        attr.value.u32 = hashField.sequence_id.value;

        attrList.push_back(attr);
    }

    if (attrList.empty())
    {
        SWSS_LOG_ERROR("Failed to create PBH hash field(%s) in HW: missing SAI attributes", hashField.key.c_str());
        return false;
    }

    sai_status_t status;
    sai_object_id_t hfOid;

    status = sai_hash_api->create_fine_grained_hash_field(&hfOid, gSwitchId, static_cast<sai_uint32_t>(attrList.size()), attrList.data());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to create PBH hash field(%s) in HW", hashField.key.c_str());
        return false;
    }

    hfObj = hashField;
    hfObj.setOid(hfOid);

    if (!this->pbhMgr.addPbhHashField(hfObj))
    {
        SWSS_LOG_ERROR("Failed to add PBH hash field(%s) to internal cache", hfObj.key.c_str());
        return false;
    }

    SWSS_LOG_NOTICE("Created PBH hash field(%s) in HW", hfObj.key.c_str());

    return true;
}

bool PbhOrch::updatePbhHashField(const PbhHashField &hashField)
{
    PbhHashField hfObj;

    if (!this->pbhMgr.getPbhHashField(hfObj, hashField.key))
    {
        SWSS_LOG_ERROR("Failed to update PBH hash field(%s) in HW: object doesn't exist", hashField.key.c_str());
        return false;
    }

    SWSS_LOG_ERROR("Failed to update PBH hash field(%s) in HW: operation is prohibited", hashField.key.c_str());

    return false;
}

bool PbhOrch::removePbhHashField(const PbhHashField &hashField)
{
    SWSS_LOG_ENTER();

    PbhHashField hfObj;

    if (!this->pbhMgr.getPbhHashField(hfObj, hashField.key))
    {
        SWSS_LOG_ERROR("Failed to remove PBH hash field(%s) from HW: object doesn't exist", hashField.key.c_str());
        return false;
    }

    sai_status_t status;

    status = sai_hash_api->remove_fine_grained_hash_field(hfObj.getOid());
    if (status != SAI_STATUS_SUCCESS)
    {
        SWSS_LOG_ERROR("Failed to remove PBH hash field(%s) from HW", hfObj.key.c_str());
        return false;
    }

    if (!this->pbhMgr.removePbhHashField(hfObj.key))
    {
        SWSS_LOG_ERROR("Failed to remove PBH hash field(%s) from internal cache", hfObj.key.c_str());
        return false;
    }

    SWSS_LOG_NOTICE("Removed PBH hash field(%s) from HW", hfObj.key.c_str());

    return true;
}

void PbhOrch::deployPbhHashFieldSetupTasks()
{
    SWSS_LOG_ENTER();

    auto &map = this->pbhMgr.hashFieldTask.pendingSetupMap;
    auto it = map.begin();

    while (it != map.end())
    {
        auto &key = it->first;
        auto &hashField = it->second;

        PbhHashField hfObj;

        if (!this->pbhMgr.getPbhHashField(hfObj, key))
        {
            if (!this->createPbhHashField(hashField))
            {
                SWSS_LOG_ERROR("Failed to create PBH hash field(%s): ASIC and CONFIG DB are diverged", key.c_str());
            }
            else
            {
                SWSS_LOG_NOTICE("Created PBH hash field(%s)", key.c_str());
            }
        }
        else
        {
            if (!this->updatePbhHashField(hashField))
            {
                SWSS_LOG_ERROR("Failed to update PBH hash field(%s): ASIC and CONFIG DB are diverged", key.c_str());
            }
            else
            {
                SWSS_LOG_NOTICE("Updated PBH hash field(%s)", key.c_str());
            }
        }

        it = map.erase(it);
    }
}

void PbhOrch::deployPbhHashFieldRemoveTasks()
{
    SWSS_LOG_ENTER();

    auto &map = this->pbhMgr.hashFieldTask.pendingRemoveMap;
    auto it = map.begin();

    while (it != map.end())
    {
        auto &key = it->first;
        auto &hashField = it->second;

        PbhHashField hfObj;

        if (!this->pbhMgr.getPbhHashField(hfObj, key))
        {
            SWSS_LOG_ERROR("Failed to remove PBH hash field(%s): object doesn't exist", key.c_str());
            it = map.erase(it);
            continue;
        }

        if (this->pbhMgr.hasDependencies(hfObj))
        {
            SWSS_LOG_WARN("Unable to remove PBH hash field(%s): object has dependencies: adding retry", key.c_str());
            it++;
            continue;
        }

        if (!this->removePbhHashField(hashField))
        {
            SWSS_LOG_ERROR("Failed to remove PBH hash field(%s): ASIC and CONFIG DB are diverged", key.c_str());
            it = map.erase(it);
            continue;
        }

        SWSS_LOG_NOTICE("Removed PBH hash field(%s)", key.c_str());

        it = map.erase(it);
    }
}

// PBH task -----------------------------------------------------------------------------------------------------------

void PbhOrch::doPbhTableTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    auto &map = consumer.m_toSync;
    auto it = map.begin();

    while (it != map.end())
    {
        auto keyOpFieldsValues = it->second;
        auto key = kfvKey(keyOpFieldsValues);
        auto op = kfvOp(keyOpFieldsValues);

        SWSS_LOG_NOTICE("KEY: %s, OP: %s", key.c_str(), op.c_str());

        if (key.empty())
        {
            SWSS_LOG_ERROR("Failed to parse PBH table key: empty string");
            it = map.erase(it);
            continue;
        }

        PbhTable table(key, op);
        table.name = key;

        if (op == SET_COMMAND)
        {
            for (const auto &cit : kfvFieldsValues(keyOpFieldsValues))
            {
                auto fieldName = fvField(cit);
                auto fieldValue = fvValue(cit);

                SWSS_LOG_NOTICE("FIELD: %s, VALUE: %s", fieldName.c_str(), fieldValue.c_str());

                table.fieldValueMap[fieldName] = fieldValue;
            }

            if (this->pbhMgr.parsePbhTable(table))
            {
                this->pbhMgr.tableTask.pendingSetupMap[table.key] = table;
            }
        }
        else if (op == DEL_COMMAND)
        {
            this->pbhMgr.tableTask.pendingRemoveMap[table.key] = table;
        }
        else
        {
            SWSS_LOG_ERROR("Unknown operation(%s)", op.c_str());
        }

        it = map.erase(it);
    }
}

void PbhOrch::doPbhRuleTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    auto &map = consumer.m_toSync;
    auto it = map.begin();

    while (it != map.end())
    {
        auto keyOpFieldsValues = it->second;
        auto key = kfvKey(keyOpFieldsValues);
        auto op = kfvOp(keyOpFieldsValues);

        SWSS_LOG_NOTICE("KEY: %s, OP: %s", key.c_str(), op.c_str());

        auto keyTokens = tokenize(key, consumer.getConsumerTable()->getTableNameSeparator()[0]);

        if (keyTokens.size() != 2)
        {
            SWSS_LOG_ERROR("Failed to parse PBH rule key(%s): invalid format", key.c_str());
            it = map.erase(it);
            continue;
        }

        auto tableName = keyTokens[0];
        auto ruleName = keyTokens[1];

        PbhRule rule(key, op);
        rule.name = ruleName;
        rule.table = tableName;

        if (op == SET_COMMAND)
        {
            for (const auto &cit : kfvFieldsValues(keyOpFieldsValues))
            {
                auto fieldName = fvField(cit);
                auto fieldValue = fvValue(cit);

                SWSS_LOG_NOTICE("FIELD: %s, VALUE: %s", fieldName.c_str(), fieldValue.c_str());

                rule.fieldValueMap[fieldName] = fieldValue;
            }

            if (this->pbhMgr.parsePbhRule(rule))
            {
                this->pbhMgr.ruleTask.pendingSetupMap[rule.key] = rule;
            }
        }
        else if (op == DEL_COMMAND)
        {
            this->pbhMgr.ruleTask.pendingRemoveMap[rule.key] = rule;
        }
        else
        {
            SWSS_LOG_ERROR("Unknown operation(%s)", op.c_str());
        }

        it = map.erase(it);
    }
}

void PbhOrch::doPbhHashTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    auto &map = consumer.m_toSync;
    auto it = map.begin();

    while (it != map.end())
    {
        auto keyOpFieldsValues = it->second;
        auto key = kfvKey(keyOpFieldsValues);
        auto op = kfvOp(keyOpFieldsValues);

        SWSS_LOG_NOTICE("KEY: %s, OP: %s", key.c_str(), op.c_str());

        if (key.empty())
        {
            SWSS_LOG_ERROR("Failed to parse PBH hash key: empty string");
            it = map.erase(it);
            continue;
        }

        PbhHash hash(key, op);

        if (op == SET_COMMAND)
        {
            for (const auto &cit : kfvFieldsValues(keyOpFieldsValues))
            {
                auto fieldName = fvField(cit);
                auto fieldValue = fvValue(cit);

                SWSS_LOG_NOTICE("FIELD: %s, VALUE: %s", fieldName.c_str(), fieldValue.c_str());

                hash.fieldValueMap[fieldName] = fieldValue;
            }

            if (this->pbhMgr.parsePbhHash(hash))
            {
                this->pbhMgr.hashTask.pendingSetupMap[hash.key] = hash;
            }
        }
        else if (op == DEL_COMMAND)
        {
            this->pbhMgr.hashTask.pendingRemoveMap[hash.key] = hash;
        }
        else
        {
            SWSS_LOG_ERROR("Unknown operation(%s)", op.c_str());
        }

        it = map.erase(it);
    }
}

void PbhOrch::doPbhHashFieldTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    auto &map = consumer.m_toSync;
    auto it = map.begin();

    while (it != map.end())
    {
        auto keyOpFieldsValues = it->second;
        auto key = kfvKey(keyOpFieldsValues);
        auto op = kfvOp(keyOpFieldsValues);

        SWSS_LOG_NOTICE("KEY: %s, OP: %s", key.c_str(), op.c_str());

        if (key.empty())
        {
            SWSS_LOG_ERROR("Failed to parse PBH hash field key: empty string");
            it = map.erase(it);
            continue;
        }

        PbhHashField hashField(key, op);

        if (op == SET_COMMAND)
        {
            for (const auto &cit : kfvFieldsValues(keyOpFieldsValues))
            {
                auto fieldName = fvField(cit);
                auto fieldValue = fvValue(cit);

                SWSS_LOG_NOTICE("FIELD: %s, VALUE: %s", fieldName.c_str(), fieldValue.c_str());

                hashField.fieldValueMap[fieldName] = fieldValue;
            }

            if (this->pbhMgr.parsePbhHashField(hashField))
            {
                this->pbhMgr.hashFieldTask.pendingSetupMap[hashField.key] = hashField;
            }
        }
        else if (op == DEL_COMMAND)
        {
            this->pbhMgr.hashFieldTask.pendingRemoveMap[hashField.key] = hashField;
        }
        else
        {
            SWSS_LOG_ERROR("Unknown operation(%s)", op.c_str());
        }

        it = map.erase(it);
    }
}

void PbhOrch::doTask(Consumer &consumer)
{
    SWSS_LOG_ENTER();

    if (!this->portsOrch->allPortsReady())
    {
        return;
    }

    auto tableName = consumer.getTableName();

    if (tableName == CFG_PBH_TABLE_TABLE_NAME)
    {
        this->doPbhTableTask(consumer);
    }
    else if (tableName == CFG_PBH_RULE_TABLE_NAME)
    {
        this->doPbhRuleTask(consumer);
    }
    else if (tableName == CFG_PBH_HASH_TABLE_NAME)
    {
        this->doPbhHashTask(consumer);
    }
    else if (tableName == CFG_PBH_HASH_FIELD_TABLE_NAME)
    {
        this->doPbhHashFieldTask(consumer);
    }
    else
    {
        SWSS_LOG_ERROR("Unknown table(%s)", tableName.c_str());
    }

    this->deployPbhHashFieldSetupTasks();
    this->deployPbhHashSetupTasks();
    this->deployPbhTableSetupTasks();
    this->deployPbhRuleSetupTasks();

    this->deployPbhRuleRemoveTasks();
    this->deployPbhTableRemoveTasks();
    this->deployPbhHashRemoveTasks();
    this->deployPbhHashFieldRemoveTasks();
}
