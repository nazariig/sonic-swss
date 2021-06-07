#ifndef SWSS_PBHCNT_H
#define SWSS_PBHCNT_H

extern "C" {
#include "saiacl.h"
#include "saihash.h"
}

#include <cstdint>

#include <unordered_map>
#include <unordered_set>
#include <string>

#include "ipaddress.h"

class PbhContainer
{
public:
    PbhContainer() = default;
    virtual ~PbhContainer() = default;

    PbhContainer(const std::string &key, const std::string &op) noexcept;

    const std::uint64_t& getRefCount() const;
    void incrementRefCount();
    void decrementRefCount();
    void clearRefCount();

    std::string key;
    std::string op;
    std::unordered_map<std::string, std::string> fieldValueMap;

protected:
    std::uint64_t refCount = 0;
};

class PbhTable : public PbhContainer
{
public:
    PbhTable() = default;
    ~PbhTable() = default;

    PbhTable(const std::string &key, const std::string &op) noexcept;

    struct {
        std::unordered_set<std::string> value;
        bool is_set = false;
    } interface_list;

    struct {
        std::string value;
        bool is_set = false;
    } description;

    std::string name;
};

class PbhRule : public PbhContainer
{
public:
    PbhRule() = default;
    ~PbhRule() = default;

    PbhRule(const std::string &key, const std::string &op) noexcept;

    struct {
        sai_uint32_t value;
        bool is_set = false;
    } priority;

    struct {
        sai_uint32_t value;
        sai_uint32_t mask;
        bool is_set = false;
    } gre_key;

    struct {
        sai_uint8_t value;
        sai_uint8_t mask;
        bool is_set = false;
    } ip_protocol;

    struct {
        sai_uint8_t value;
        sai_uint8_t mask;
        bool is_set = false;
    } ipv6_next_header;

    struct {
        sai_uint16_t value;
        sai_uint16_t mask;
        bool is_set = false;
    } l4_dst_port;

    struct {
        sai_uint16_t value;
        sai_uint16_t mask;
        bool is_set = false;
    } inner_ether_type;

    struct {
        std::string value;
        bool is_set = false;
    } hash;

    struct {
        sai_acl_entry_attr_t value;
        bool is_set = false;
    } packet_action;

    struct {
        bool value;
        bool is_set = false;
    } flow_counter;

    std::string name;
    std::string table;
};

class PbhHash : public PbhContainer
{
public:
    PbhHash() = default;
    ~PbhHash() = default;

    PbhHash(const std::string &key, const std::string &op) noexcept;

    const sai_object_id_t& getOid() const noexcept;
    void setOid(const sai_object_id_t &oid) noexcept;

    struct {
        std::unordered_set<std::string> value;
        bool is_set = false;
    } hash_field_list;

private:
    sai_object_id_t oid = SAI_NULL_OBJECT_ID;
};

class PbhHashField : public PbhContainer
{
public:
    PbhHashField() = default;
    ~PbhHashField() = default;

    PbhHashField(const std::string &key, const std::string &op) noexcept;

    const sai_object_id_t& getOid() const noexcept;
    void setOid(const sai_object_id_t &oid) noexcept;

    struct {
        sai_native_hash_field_t value;
        bool is_set = false;
    } hash_field;

    struct {
        swss::IpAddress value;
        bool is_set = false;
    } ip_mask;

    struct {
        sai_uint32_t value;
        bool is_set = false;
    } sequence_id;

private:
    sai_object_id_t oid = SAI_NULL_OBJECT_ID;
};

#endif /* SWSS_PBHCNT_H */
