// includes -----------------------------------------------------------------------------------------------------------

#include <unordered_map>
#include <string>

#include <tokenize.h>

#include "bufferschema.h"

#include "buffercache.h"

using namespace swss;

// types --------------------------------------------------------------------------------------------------------------

//template<typename T>
//using BufferConfigMap_t = std::unordered_map<std::string, T>;

// Buffer Cache -- ----------------------------------------------------------------------------------------------------




/*
template<>
bool PbhHelper::incRefCount(const PbhRule &obj)
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
bool BufferCache::parseBufferConfig(const BufferProfileConfig &cfg)
{

}

template<>
bool BufferCache::parseBufferConfig(const BufferProfileConfig &cfg)
{

}


template<typename T>
bool PbhHelper::getPbhObj(T &obj, const std::string &key) const
{
    const auto &objMap = this->getPbhObjMap<T>();

    const auto &cit = objMap.find(key);
    if (cit == objMap.cend())
    {
        return false;
    }

    obj = cit->second;

    return true;
}

template bool BufferCache::getPbhObj(PbhTable &obj, const std::string &key) const;
template bool BufferCache::getPbhObj(PbhRule &obj, const std::string &key) const;
template bool BufferCache::getPbhObj(PbhHash &obj, const std::string &key) const;
template bool BufferCache::getPbhObj(PbhHashField &obj, const std::string &key) const;





getBufferConfig<BufferProfileConfig>();


std::unordered_map<std::string, BufferProfileConfig> profMap;
std::unordered_map<std::string, PriorityGroupConfig> pgMap;
std::unordered_map<std::string, IngressBufferProfileListConfig> iBufProfListMap;
std::unordered_map<std::string, EgressBufferProfileListConfig> eBufProfListMap;






template<>
auto BufferCache::getBufferObjMap() const -> const std::unordered_map<std::string, BufferProfileConfig>&
{
    return profMap;
}

template<>
auto BufferCache::getBufferObjMap() const -> const std::unordered_map<std::string, PriorityGroupConfig>&
{
    return pgMap;
}

template<>
auto BufferCache::getBufferObjMap() const -> const std::unordered_map<std::string, IngressBufferProfileListConfig>&
{
    return iBufProfListMap;
}

template<>
auto BufferCache::getBufferObjMap() const -> const std::unordered_map<std::string, EgressBufferProfileListConfig>&
{
    return eBufProfListMap;
}

template<typename T>
bool BufferCache::parseBufferConfig(T &cfg, const KeyOpFieldsValuesTuple &entry) const
{
    const auto &objMap = getBufferObjMap<T>();


    for (const auto &cit : fvList)
    {
        auto fieldName = fvField(cit);
        auto fieldValue = fvValue(cit);

        cfg.fieldValueMap[fieldName] = fieldValue;
    }






    const auto &objMap = this->getPbhObjMap<T>();

    const auto &cit = objMap.find(key);
    if (cit == objMap.cend())
    {
        return false;
    }

    obj = cit->second;

    return true;
}

template bool BufferCache::getPbhObj(PbhTable &obj, const std::string &key) const;
template bool BufferCache::getPbhObj(PbhRule &obj, const std::string &key) const;
template bool BufferCache::getPbhObj(PbhHash &obj, const std::string &key) const;
template bool BufferCache::getPbhObj(PbhHashField &obj, const std::string &key) const;
*/























/*void BufferCache::parseConfig(const KeyOpFieldsValuesTuple &entry)
{
    auto key = kfvKey(entry);
    auto fvList = kfvFieldsValues(entry);

    BufferProfileConfig cfg;
    getBufferProfileCache(cfg, key);

    for (const auto &cit : fvList)
    {
        auto fieldName = fvField(cit);
        auto fieldValue = fvValue(cit);

        cfg.fieldValueMap[fieldName] = fieldValue;
    }

    const auto &cit = cfg.fieldValueMap.find(BUFFER_PROFILE_PACKET_DISCARD_ACTION);
    if (cit != cfg.fieldValueMap.cend())
    {
        cfg.isTrimmingEligible = cit->second == BUFFER_PROFILE_PACKET_DISCARD_ACTION_TRIM ? true : false;
    }

    profMap[key] = cfg;
}*/


// ----------------------------------------------------------------------------------



/*void BufferCache::setBufferProfileCache(const KeyOpFieldsValuesTuple &entry)
{
    auto key = kfvKey(entry);
    auto fvList = kfvFieldsValues(entry);

    BufferProfileConfig cfg;
    getBufferProfileCache(cfg, key);

    for (const auto &cit : fvList)
    {
        auto fieldName = fvField(cit);
        auto fieldValue = fvValue(cit);

        cfg.fieldValueMap[fieldName] = fieldValue;
    }

    const auto &cit = cfg.fieldValueMap.find(BUFFER_PROFILE_PACKET_DISCARD_ACTION);
    if (cit != cfg.fieldValueMap.cend())
    {
        cfg.isTrimmingEligible = cit->second == BUFFER_PROFILE_PACKET_DISCARD_ACTION_TRIM ? true : false;
    }

    profMap[key] = cfg;
}

void BufferCache::delBufferProfileCache(const std::string &key)
{
    const auto &cit = profMap.find(key);
    if (cit == profMap.cend())
    {
        return;
    }

    profMap.erase(cit);
}

bool BufferCache::getBufferProfileCache(BufferProfileConfig &cfg, const std::string &key)
{
    const auto &cit = profMap.find(key);
    if (cit != profMap.cend())
    {
        cfg = cit->second;
        return true;
    }

    return false;
}*/

// ------------------------------


/*void BufferCache::setPriorityGroupCache(const swss::KeyOpFieldsValuesTuple &entry)
{

}

void BufferCache::delBufferProfileCache(const std::string &key)
{

}

bool BufferCache::getPriorityGroupCache(PriorityGroupConfig &cfg, const std::string &key)
{

}*/


//======================================================================
/*
void BufferCache::setIngressBufferProfileListCache(const std::string &key, const IngressBufferProfileListConfig &cfg)
{
    IngressBufferProfileListConfig oldCfg;

    if (getIngressBufferProfileListCache(oldCfg, key))
    {
        oldCfg.fieldValue.insert(cfg.begin(), cfg.end());
        iBufProfListMap[key] = oldCfg;

        //for (const auto &cit : cfg.fieldValueMap)
        //{
        //    auto fieldName = fvField(cit);
        //    auto fieldValue = fvValue(cit);
    
        //    cfg.fieldValueMap[fieldName] = fieldValue;
        //}

        
    }
    else
    {
        iBufProfListMap[key] = cfg;
    }
}

void BufferCache::setEgressBufferProfileListCache(const std::string &key, const EgressBufferProfileListConfig &cfg)
{
    EgressBufferProfileListConfig oldCfg;

    if (getEgressBufferProfileListCache(oldCfg, key))
    {
        oldCfg.fieldValue.insert(cfg.begin(), cfg.end());
        eBufProfListMap[key] = oldCfg;
    }
    else
    {
        eBufProfListMap[key] = cfg;
    }
}

bool BufferCache::getEgressBufferProfileListCache(EgressBufferProfileListConfig &cfg, const std::string &key)
{
    const auto &cit = eBufProfListMap.find(key);
    if (cit != eBufProfListMap.cend())
    {
        cfg = cit->second;
        return true;
    }

    return false;
}*/

// ====================================================================================================================

template<>
void BufferCache::setObjRef(const BufferProfileConfig &cfg)
{
    // No actions are required
}

template<>
void BufferCache::setObjRef(const PriorityGroupConfig &cfg)
{
    if (cfg.profile.is_set)
    {
        const auto &cit = profMap.find(cfg.profile.value);
        if (cit != profMap.cend())
        {
            cit->second.pgRefCount++;
        }
    }
}

template<>
void BufferCache::setObjRef(const IngressBufferProfileListConfig &cfg)
{
    if (cfg.profile_list.is_set)
    {
        for (const auto &cit1 : cfg.profile_list.value)
        {
            const auto &cit2 = profMap.find(cit1);
            if (cit2 != profMap.cend())
            {
                cit2->second.iBufProfListRefCount++;
            }
        }
    }
}

template<>
void BufferCache::setObjRef(const EgressBufferProfileListConfig &cfg)
{
    if (cfg.profile_list.is_set)
    {
        for (const auto &cit1 : cfg.profile_list.value)
        {
            const auto &cit2 = profMap.find(cit1);
            if (cit2 != profMap.cend())
            {
                cit2->second.eBufProfListRefCount++;
            }
        }
    }
}

template<>
void BufferCache::delObjRef(const BufferProfileConfig &cfg)
{
    // No actions are required
}

template<>
void BufferCache::delObjRef(const PriorityGroupConfig &cfg)
{
    if (cfg.profile.is_set)
    {
        const auto &cit = profMap.find(cfg.profile.value);
        if (cit != profMap.cend())
        {
            cit->second.pgRefCount--;
        }
    }
}

template<>
void BufferCache::delObjRef(const IngressBufferProfileListConfig &cfg)
{
    if (cfg.profile_list.is_set)
    {
        for (const auto &cit1 : cfg.profile_list.value)
        {
            const auto &cit2 = profMap.find(cit1);
            if (cit2 != profMap.cend())
            {
                cit2->second.iBufProfListRefCount--;
            }
        }
    }
}

template<>
void BufferCache::delObjRef(const EgressBufferProfileListConfig &cfg)
{
    if (cfg.profile_list.is_set)
    {
        for (const auto &cit1 : cfg.profile_list.value)
        {
            const auto &cit2 = profMap.find(cit1);
            if (cit2 != profMap.cend())
            {
                cit2->second.eBufProfListRefCount--;
            }
        }
    }
}

template<>
void BufferCache::parseBufferConfig(BufferProfileConfig &cfg) const
{
    auto &map = cfg.fieldValueMap;

    const auto &cit = map.find(BUFFER_PROFILE_PACKET_DISCARD_ACTION);
    if (cit != map.cend())
    {
        cfg.isTrimmingEligible = cit->second == BUFFER_PROFILE_PACKET_DISCARD_ACTION_TRIM ? true : false;
    }
}

template<>
void BufferCache::parseBufferConfig(PriorityGroupConfig &cfg) const
{
    auto &map = cfg.fieldValueMap;

    const auto &cit = map.find(BUFFER_PG_PROFILE);
    if (cit != map.cend())
    {
        cfg.profile.value = cit->second;
        cfg.profile.is_set = true;
    }
}

template<>
void BufferCache::parseBufferConfig(IngressBufferProfileListConfig &cfg) const
{
    auto &map = cfg.fieldValueMap;

    const auto &cit = map.find(BUFFER_PORT_INGRESS_PROFILE_LIST_PROFILE_LIST);
    if (cit != map.cend())
    {
        auto profList = tokenize(cit->second, ',');

        cfg.profile_list.value.insert(profList.begin(), profList.end());
        cfg.profile_list.is_set = true;
    }
}

template<>
void BufferCache::parseBufferConfig(EgressBufferProfileListConfig &cfg) const
{
    auto &map = cfg.fieldValueMap;

    const auto &cit = map.find(BUFFER_PORT_EGRESS_PROFILE_LIST_PROFILE_LIST);
    if (cit != map.cend())
    {
        auto profList = tokenize(cit->second, ',');

        cfg.profile_list.value.insert(profList.begin(), profList.end());
        cfg.profile_list.is_set = true;
    }
}

template<>
auto BufferCache::getBufferObjMap() const -> const std::unordered_map<std::string, BufferProfileConfig>&
{
    return profMap;
}

template<>
auto BufferCache::getBufferObjMap() const -> const std::unordered_map<std::string, PriorityGroupConfig>&
{
    return pgMap;
}

template<>
auto BufferCache::getBufferObjMap() const -> const std::unordered_map<std::string, IngressBufferProfileListConfig>&
{
    return iBufProfListMap;
}

template<>
auto BufferCache::getBufferObjMap() const -> const std::unordered_map<std::string, EgressBufferProfileListConfig>&
{
    return eBufProfListMap;
}

template<>
auto BufferCache::getBufferObjMap() -> std::unordered_map<std::string, BufferProfileConfig>&
{
    return profMap;
}

template<>
auto BufferCache::getBufferObjMap() -> std::unordered_map<std::string, PriorityGroupConfig>&
{
    return pgMap;
}

template<>
auto BufferCache::getBufferObjMap() -> std::unordered_map<std::string, IngressBufferProfileListConfig>&
{
    return iBufProfListMap;
}

template<>
auto BufferCache::getBufferObjMap() -> std::unordered_map<std::string, EgressBufferProfileListConfig>&
{
    return eBufProfListMap;
}

template<typename T>
void BufferCache::setBufferCache(const std::string &key, const T &cfg)
{
    auto &map = getBufferObjMap<T>();

    const auto &cit = map.find(key);
    if (cit != map.cend())
    {
        delObjRef(cit->second);
    }
    setObjRef(cfg);

    map[key] = cfg;
}

template void BufferCache::setBufferCache(const std::string &key, const BufferProfileConfig &cfg);
template void BufferCache::setBufferCache(const std::string &key, const PriorityGroupConfig &cfg);
template void BufferCache::setBufferCache(const std::string &key, const IngressBufferProfileListConfig &cfg);
template void BufferCache::setBufferCache(const std::string &key, const EgressBufferProfileListConfig &cfg);

template<typename T>
bool BufferCache::getBufferCache(T &cfg, const std::string &key) const
{
    auto &map = getBufferObjMap<T>();

    const auto &cit = map.find(key);
    if (cit != map.cend())
    {
        cfg = cit->second;
        return true;
    }

    return false;
}

template bool BufferCache::getBufferCache(BufferProfileConfig &cfg, const std::string &key) const;
template bool BufferCache::getBufferCache(PriorityGroupConfig &cfg, const std::string &key) const;
template bool BufferCache::getBufferCache(IngressBufferProfileListConfig &cfg, const std::string &key) const;
template bool BufferCache::getBufferCache(EgressBufferProfileListConfig &cfg, const std::string &key) const;

void BufferCache::delBufferProfileCache(const std::string &key)
{
    const auto &cit = profMap.find(key);
    if (cit == profMap.cend())
    {
        return;
    }

    delObjRef(cit->second);
    profMap.erase(cit);
}

void BufferCache::delPriorityGroupCache(const std::string &key)
{
    const auto &cit = pgMap.find(key);
    if (cit == pgMap.cend())
    {
        return;
    }

    delObjRef(cit->second);
    pgMap.erase(cit);
}

void BufferCache::delIngressBufferProfileListCache(const std::string &key)
{
    const auto &cit = iBufProfListMap.find(key);
    if (cit == iBufProfListMap.cend())
    {
        return;
    }

    delObjRef(cit->second);
    iBufProfListMap.erase(cit);
}

void BufferCache::delEgressBufferProfileListCache(const std::string &key)
{
    const auto &cit = eBufProfListMap.find(key);
    if (cit == eBufProfListMap.cend())
    {
        return;
    }

    delObjRef(cit->second);
    eBufProfListMap.erase(cit);
}
















/*template<>
void BufferCache::setBufferCache(const std::string &key, const BufferProfileConfig &cfg)
{
    profMap[key] = cfg;
}

template<>
void BufferCache::setBufferCache(const std::string &key, const PriorityGroupConfig &cfg)
{
    pgMap[key] = cfg;
}

template<>
void BufferCache::setBufferCache(const std::string &key, const IngressBufferProfileListConfig &cfg)
{
    iBufProfListMap[key] = cfg;
}

template<>
void BufferCache::setBufferCache(const std::string &key, const EgressBufferProfileListConfig &cfg)
{
    eBufProfListMap[key] = cfg;
}*/




/*
template<>
bool BufferCache::getBufferCache(BufferProfileConfig &cfg, const std::string &key) const
{
    const auto &cit = profMap.find(key);
    if (cit != profMap.cend())
    {
        cfg = cit->second;
        return true;
    }

    return false;
}

template<>
bool BufferCache::getBufferCache(PriorityGroupConfig &cfg, const std::string &key) const
{
    const auto &cit = pgMap.find(key);
    if (cit != pgMap.cend())
    {
        cfg = cit->second;
        return true;
    }

    return false;
}

template<>
bool BufferCache::getBufferCache(IngressBufferProfileListConfig &cfg, const std::string &key) const
{
    const auto &cit = iBufProfListMap.find(key);
    if (cit != iBufProfListMap.cend())
    {
        cfg = cit->second;
        return true;
    }

    return false;
}

template<>
bool BufferCache::getBufferCache(EgressBufferProfileListConfig &cfg, const std::string &key) const
{
    const auto &cit = eBufProfListMap.find(key);
    if (cit != eBufProfListMap.cend())
    {
        cfg = cit->second;
        return true;
    }

    return false;
}*/


