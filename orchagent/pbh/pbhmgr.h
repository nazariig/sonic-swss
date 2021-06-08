#ifndef SWSS_PBHMGR_H
#define SWSS_PBHMGR_H

#include "pbhcnt.h"

class PbhManager
{
public:
    PbhManager() = default;
    ~PbhManager() = default;

    static std::uint8_t toUInt8(const std::string &hexStr);
    static std::uint16_t toUInt16(const std::string &hexStr);
    static std::uint32_t toUInt32(const std::string &hexStr);

    template<typename T>
    bool hasDependencies(const T &obj) const;
    template<typename T>
    bool validateDependencies(const T &obj) const;
    template<typename T>
    bool addDependencies(const T &obj);
    template<typename T>
    bool removeDependencies(const T &obj);

    bool getPbhTable(PbhTable &table, const std::string &key) const;
    bool getPbhRule(PbhRule &rule, const std::string &key) const;
    bool getPbhHash(PbhHash &hash, const std::string &key) const;
    bool getPbhHashField(PbhHashField &hashField, const std::string &key) const;

    bool addPbhTable(const PbhTable &table);
    bool updatePbhTable(const PbhTable &table);
    bool removePbhTable(const std::string &key);

    bool addPbhRule(const PbhRule &rule);
    bool updatePbhRule(const PbhRule &rule);
    bool removePbhRule(const std::string &key);

    bool addPbhHash(const PbhHash &hash);
    bool updatePbhHash(const PbhHash &hash);
    bool removePbhHash(const std::string &key);

    bool addPbhHashField(const PbhHashField &hashField);
    bool updatePbhHashField(const PbhHashField &hashField);
    bool removePbhHashField(const std::string &key);

    bool parsePbhTable(PbhTable &table) const;
    bool parsePbhRule(PbhRule &rule) const;
    bool parsePbhHash(PbhHash &hash) const;
    bool parsePbhHashField(PbhHashField &hashField) const;

private:
    bool parsePbhTableInterfaceList(PbhTable &table, const std::string &field, const std::string &value) const;
    bool parsePbhTableDescription(PbhTable &table, const std::string &field, const std::string &value) const;

    bool parsePbhRulePriority(PbhRule &rule, const std::string &field, const std::string &value) const;
    bool parsePbhRuleGreKey(PbhRule &rule, const std::string &field, const std::string &value) const;
    bool parsePbhRuleIpProtocol(PbhRule &rule, const std::string &field, const std::string &value) const;
    bool parsePbhRuleIpv6NextHeader(PbhRule &rule, const std::string &field, const std::string &value) const;
    bool parsePbhRuleL4DstPort(PbhRule &rule, const std::string &field, const std::string &value) const;
    bool parsePbhRuleInnerEtherType(PbhRule &rule, const std::string &field, const std::string &value) const;
    bool parsePbhRuleHash(PbhRule &rule, const std::string &field, const std::string &value) const;
    bool parsePbhRulePacketAction(PbhRule &rule, const std::string &field, const std::string &value) const;
    bool parsePbhRuleFlowCounter(PbhRule &rule, const std::string &field, const std::string &value) const;

    bool parsePbhHashHashFieldList(PbhHash &hash, const std::string &field, const std::string &value) const;

    bool parsePbhHashFieldHashField(PbhHashField &hashField, const std::string &field, const std::string &value) const;
    bool parsePbhHashFieldIpMask(PbhHashField &hashField, const std::string &field, const std::string &value) const;
    bool parsePbhHashFieldSequenceId(PbhHashField &hashField, const std::string &field, const std::string &value) const;

    bool validatePbhTable(PbhTable &table) const;
    bool validatePbhRule(PbhRule &rule) const;
    bool validatePbhHash(PbhHash &hash) const;
    bool validatePbhHashField(PbhHashField &hashField) const;

    bool isIpv4MaskRequired(const sai_native_hash_field_t &value) const;
    bool isIpv6MaskRequired(const sai_native_hash_field_t &value) const;

public:
    struct {
        std::unordered_map<std::string, PbhTable> pendingSetupMap;
        std::unordered_map<std::string, PbhTable> pendingRemoveMap;
    } tableTask;

    struct {
        std::unordered_map<std::string, PbhRule> pendingSetupMap;
        std::unordered_map<std::string, PbhRule> pendingRemoveMap;
    } ruleTask;

    struct {
        std::unordered_map<std::string, PbhHash> pendingSetupMap;
        std::unordered_map<std::string, PbhHash> pendingRemoveMap;
    } hashTask;

    struct {
        std::unordered_map<std::string, PbhHashField> pendingSetupMap;
        std::unordered_map<std::string, PbhHashField> pendingRemoveMap;
    } hashFieldTask;

private:
    std::unordered_map<std::string, PbhTable> tableMap;
    std::unordered_map<std::string, PbhRule> ruleMap;
    std::unordered_map<std::string, PbhHash> hashMap;
    std::unordered_map<std::string, PbhHashField> hashFieldMap;
};

#endif /* SWSS_PBHMGR_H */
