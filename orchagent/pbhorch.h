#ifndef SWSS_PBHORCH_H
#define SWSS_PBHORCH_H

#include <vector>

#include "orch.h"
#include "aclorch.h"
#include "portsorch.h"

#include "pbh/pbhmgr.h"

class PbhOrch : public Orch
{
public:
    PbhOrch(
        std::vector<TableConnector> &connectorList,
        AclOrch *aclOrch,
        PortsOrch *portsOrch
    );
    ~PbhOrch();

    using Orch::doTask;  // Allow access to the basic doTask

private:
    bool createPbhTable(const PbhTable &table);
    bool updatePbhTable(const PbhTable &table);
    bool removePbhTable(const PbhTable &table);

    void deployPbhTableSetupTasks();
    void deployPbhTableRemoveTasks();

    bool createPbhRule(const PbhRule &rule);
    bool updatePbhRule(const PbhRule &rule);
    bool removePbhRule(const PbhRule &rule);

    void deployPbhRuleSetupTasks();
    void deployPbhRuleRemoveTasks();

    bool createPbhHash(const PbhHash &hash);
    bool updatePbhHash(const PbhHash &hash);
    bool removePbhHash(const PbhHash &hash);

    void deployPbhHashSetupTasks();
    void deployPbhHashRemoveTasks();

    bool createPbhHashField(const PbhHashField &hashField);
    bool updatePbhHashField(const PbhHashField &hashField);
    bool removePbhHashField(const PbhHashField &hashField);

    void deployPbhHashFieldSetupTasks();
    void deployPbhHashFieldRemoveTasks();

    void doPbhTableTask(Consumer &consumer);
    void doPbhRuleTask(Consumer &consumer);
    void doPbhHashTask(Consumer &consumer);
    void doPbhHashFieldTask(Consumer &consumer);
    void doTask(Consumer &consumer);

    AclOrch *aclOrch;
    PortsOrch *portsOrch;

    PbhManager pbhMgr;
};

#endif /* SWSS_PBHORCH_H */
