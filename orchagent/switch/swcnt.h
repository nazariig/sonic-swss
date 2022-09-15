#pragma once

extern "C" {
#include "saihash.h"
}

#include <unordered_map>
#include <set>
#include <string>

class SwitchContainer
{
public:
    SwitchContainer() = default;
    virtual ~SwitchContainer() = default;

    std::unordered_map<std::string, std::string> fieldValueMap;
};

class SwitchHash final : public SwitchContainer
{
public:
    SwitchHash() = default;
    ~SwitchHash() = default;

    struct {
        std::set<sai_native_hash_field_t> value;
        bool is_set = false;
    } ecmp_hash;

    struct {
        std::set<sai_native_hash_field_t> value;
        bool is_set = false;
    } lag_hash;
};
