#pragma once

#include <unordered_map>
#include <unordered_set>
#include <string>

/*class PbhContainer
{
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
};*/



class BufferContainer
{
public:
    BufferContainer() = default;
    virtual ~BufferContainer() = default;

    std::unordered_map<std::string, std::string> fieldValueMap;
};

class BufferProfileConfig final : public BufferContainer
{
public:
    BufferProfileConfig() = default;
    ~BufferProfileConfig() = default;

    inline bool isTrimmingProhibited() const
    {
        return ((pgRefCount > 0) || (iBufProfListRefCount > 0) || (eBufProfListRefCount)) ? true : false;
    }



    //bool 

    //std::uint64_t pgRefCount = 0;


    //std::unordered_set<std::string> pgRef;
    //std::unordered_set<std::string> iBufProfListRef;
    //std::unordered_set<std::string> eBufProfListRef;

    std::uint64_t pgRefCount = 0;
    std::uint64_t iBufProfListRefCount = 0;
    std::uint64_t eBufProfListRefCount = 0;

    bool isTrimmingEligible = false;
};

class PriorityGroupConfig final : public BufferContainer
{
public:
    PriorityGroupConfig() = default;
    ~PriorityGroupConfig() = default;

    struct {
        std::string value;
        bool is_set = false;
    } profile;
};

class IngressBufferProfileListConfig final : public BufferContainer
{
public:
    IngressBufferProfileListConfig() = default;
    ~IngressBufferProfileListConfig() = default;

    struct {
        std::unordered_set<std::string> value;
        bool is_set = false;
    } profile_list;
};

class EgressBufferProfileListConfig final : public BufferContainer
{
public:
    EgressBufferProfileListConfig() = default;
    ~EgressBufferProfileListConfig() = default;

    struct {
        std::unordered_set<std::string> value;
        bool is_set = false;
    } profile_list;
};




//task_process_status processIngressBufferProfileList(KeyOpFieldsValuesTuple &tuple);
//task_process_status processEgressBufferProfileList(KeyOpFieldsValuesTuple &tuple);