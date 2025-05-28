#pragma once

#include <unordered_map>
#include <string>

//#include <table.h>

#include "buffercontainer.h"

class BufferCache final
{
public:
    BufferCache() = default;
    ~BufferCache() = default;

    template<typename T>
    void parseBufferConfig(T &cfg) const;

    template<typename T>
    void setBufferCache(const std::string &key, const T &cfg);
    template<typename T>
    bool getBufferCache(T &cfg, const std::string &key) const;

    void delBufferProfileCache(const std::string &key);
    void delPriorityGroupCache(const std::string &key);
    void delIngressBufferProfileListCache(const std::string &key);
    void delEgressBufferProfileListCache(const std::string &key);






    //template<typename T>
    //void parseBufferConfig(T &cfg, const KeyOpFieldsValuesTuple &entry) const;


    //template<typename T>
    //void parseBufferConfig();

    /*void setBufferProfileCache(const swss::KeyOpFieldsValuesTuple &entry);
    void delBufferProfileCache(const std::string &key);
    bool getBufferProfileCache(BufferProfileConfig &cfg, const std::string &key) const;

    void setPriorityGroupCache(const swss::KeyOpFieldsValuesTuple &entry);
    void delBufferProfileCache(const std::string &key);
    bool getPriorityGroupCache(PriorityGroupConfig &cfg, const std::string &key) const;

    void setIngressBufferProfileListCache(const swss::KeyOpFieldsValuesTuple &entry);
    void delIngressBufferProfileListCache(const std::string &key);
    bool getIngressBufferProfileListCache(PriorityGroupConfig &cfg, const std::string &key) const;

    void setEgressBufferProfileListCache(const swss::KeyOpFieldsValuesTuple &entry);
    void delEgressBufferProfileListCache(const std::string &key);
    bool getEgressBufferProfileListCache(PriorityGroupConfig &cfg, const std::string &key) const;*/

private:
    template<typename T>
    auto getBufferObjMap() const -> const std::unordered_map<std::string, T>&;
    template<typename T>
    auto getBufferObjMap() -> std::unordered_map<std::string, T>&;

    template<typename T>
    void setObjRef(const T &cfg);
    template<typename T>
    void delObjRef(const T &cfg);




    //template<typename T>
    //void getBufferObjMap();

    std::unordered_map<std::string, BufferProfileConfig> profMap;
    std::unordered_map<std::string, PriorityGroupConfig> pgMap;
    std::unordered_map<std::string, IngressBufferProfileListConfig> iBufProfListMap;
    std::unordered_map<std::string, EgressBufferProfileListConfig> eBufProfListMap;






/*
public:
    PbhContainer() = default;
    virtual ~PbhContainer() = default;

    PbhContainer(const std::string &key, const std::string &op) noexcept;

    std::uint64_t getRefCount() const noexcept;
    void incrementRefCount() noexcept;
    void decrementRefCount() noexcept;
    void clearRefCount() noexcept;

    std::string key;
    std::string op;
    std::unordered_map<std::string, std::string> fieldValueMap;

protected:
    std::uint64_t refCount = 0;


private:
    std::unordered_map<std::string, std::string> fieldValueMap;*/
};
