import pytest
import logging


PBH_HASH_FIELD_NAME = "inner_ip_proto"
PBH_HASH_FIELD_HASH_FIELD = "INNER_IP_PROTOCOL"
PBH_HASH_FIELD_SEQUENCE_ID = "1"

PBH_HASH_NAME = "inner_v4_hash"
PBH_HASH_HASH_FIELD_LIST = ["inner_ip_proto"]

PBH_RULE_NAME = "nvgre"
PBH_RULE_PRIORITY = "1"
PBH_RULE_GRE_KEY = "0x2500/0xffffff00"
PBH_RULE_INNER_ETHER_TYPE = "0x86dd/0xffff"
PBH_RULE_HASH = "inner_v4_hash"

PBH_TABLE_NAME = "pbh_table"
PBH_TABLE_INTERFACE_LIST = ["Ethernet0", "Ethernet4"]
PBH_TABLE_DESCRIPTION = "NVGRE and VxLAN"


logging.basicConfig(level=logging.INFO)
pbhlogger = logging.getLogger(__name__)


@pytest.mark.usefixtures("dvs_lag_manager")
class TestPbhInterfaceBinding:
    def test_PbhTablePortBinding(self, testlog, dvs_pbh, dvs_acl):
        try:
            port_list = ["Ethernet0", "Ethernet4"]

            pbhlogger.info("Create PBH table: {}".format(PBH_TABLE_NAME))
            dvs_pbh.create_pbh_table(
                table_name=PBH_TABLE_NAME,
                interface_list=port_list,
                description=PBH_TABLE_DESCRIPTION
            )
            dvs_acl.verify_acl_table_count(1)

            pbhlogger.info("Validate PBH table port binding: {}".format(",".join(port_list)))
            acl_table_id = dvs_acl.get_acl_table_ids(1)[0]
            acl_table_group_ids = dvs_acl.get_acl_table_group_ids(len(port_list))

            dvs_acl.verify_acl_table_group_members(acl_table_id, acl_table_group_ids, 1)
            dvs_acl.verify_acl_table_port_binding(acl_table_id, port_list, 1)
        finally:
            pbhlogger.info("Remove PBH table: {}".format(PBH_TABLE_NAME))
            dvs_pbh.remove_pbh_table(PBH_TABLE_NAME)
            dvs_acl.verify_acl_table_count(0)

    def test_PbhTablePortChannelBinding(self, testlog, dvs_pbh, dvs_acl):
        try:
            # PortChannel0001
            pbhlogger.info("Create LAG: PortChannel0001")
            self.dvs_lag.create_port_channel("0001")
            self.dvs_lag.get_and_verify_port_channel(1)

            pbhlogger.info("Create LAG member: Ethernet120")
            self.dvs_lag.create_port_channel_member("0001", "Ethernet120")
            self.dvs_lag.get_and_verify_port_channel_members(1)

            # PortChannel0002
            pbhlogger.info("Create LAG: PortChannel0002")
            self.dvs_lag.create_port_channel("0002")
            self.dvs_lag.get_and_verify_port_channel(2)

            pbhlogger.info("Create LAG member: Ethernet124")
            self.dvs_lag.create_port_channel_member("0002", "Ethernet124")
            self.dvs_lag.get_and_verify_port_channel_members(2)

            # PBH table
            portchannel_list = ["PortChannel0001", "PortChannel0002"]

            pbhlogger.info("Create PBH table: {}".format(PBH_TABLE_NAME))
            dvs_pbh.create_pbh_table(
                table_name=PBH_TABLE_NAME,
                interface_list=portchannel_list,
                description=PBH_TABLE_DESCRIPTION
            )
            dvs_acl.verify_acl_table_count(1)

            pbhlogger.info("Validate PBH table LAG binding: {}".format(",".join(portchannel_list)))
            acl_table_id = dvs_acl.get_acl_table_ids(1)[0]
            acl_table_group_ids = dvs_acl.get_acl_table_group_ids(len(portchannel_list))

            dvs_acl.verify_acl_table_group_members(acl_table_id, acl_table_group_ids, 1)
            dvs_acl.verify_acl_table_portchannel_binding(acl_table_id, portchannel_list, 1)
        finally:
            # PBH table
            pbhlogger.info("Remove PBH table: {}".format(PBH_TABLE_NAME))
            dvs_pbh.remove_pbh_table(PBH_TABLE_NAME)
            dvs_acl.verify_acl_table_count(0)

            # PortChannel0001
            pbhlogger.info("Remove LAG member: Ethernet120")
            self.dvs_lag.remove_port_channel_member("0001", "Ethernet120")
            self.dvs_lag.get_and_verify_port_channel_members(1)

            pbhlogger.info("Remove LAG: PortChannel0001")
            self.dvs_lag.remove_port_channel("0001")
            self.dvs_lag.get_and_verify_port_channel(1)

            # PortChannel0002
            pbhlogger.info("Remove LAG member: Ethernet124")
            self.dvs_lag.remove_port_channel_member("0002", "Ethernet124")
            self.dvs_lag.get_and_verify_port_channel_members(0)

            pbhlogger.info("Remove LAG: PortChannel0002")
            self.dvs_lag.remove_port_channel("0002")
            self.dvs_lag.get_and_verify_port_channel(0)


class TestPbhBasicFlows:
    def test_PbhHashFieldCreationDeletion(self, testlog, dvs_pbh):
        try:
            pbhlogger.info("Create PBH hash field: {}".format(PBH_HASH_FIELD_NAME))
            dvs_pbh.create_pbh_hash_field(
                hash_field_name=PBH_HASH_FIELD_NAME,
                hash_field=PBH_HASH_FIELD_HASH_FIELD,
                sequence_id=PBH_HASH_FIELD_SEQUENCE_ID
            )
            dvs_pbh.verify_pbh_hash_field_count(1)
        finally:
            pbhlogger.info("Remove PBH hash field: {}".format(PBH_HASH_FIELD_NAME))
            dvs_pbh.remove_pbh_hash_field(PBH_HASH_FIELD_NAME)
            dvs_pbh.verify_pbh_hash_field_count(0)

    def test_PbhHashCreationDeletion(self, testlog, dvs_pbh):
        try:
            # PBH hash field
            pbhlogger.info("Create PBH hash field: {}".format(PBH_HASH_FIELD_NAME))
            dvs_pbh.create_pbh_hash_field(
                hash_field_name=PBH_HASH_FIELD_NAME,
                hash_field=PBH_HASH_FIELD_HASH_FIELD,
                sequence_id=PBH_HASH_FIELD_SEQUENCE_ID
            )
            dvs_pbh.verify_pbh_hash_field_count(1)

            # PBH hash
            pbhlogger.info("Create PBH hash: {}".format(PBH_HASH_NAME))
            dvs_pbh.create_pbh_hash(
                hash_name=PBH_HASH_NAME,
                hash_field_list=PBH_HASH_HASH_FIELD_LIST
            )
            dvs_pbh.verify_pbh_hash_count(1)
        finally:
            # PBH hash
            pbhlogger.info("Remove PBH hash: {}".format(PBH_HASH_NAME))
            dvs_pbh.remove_pbh_hash(PBH_HASH_NAME)
            dvs_pbh.verify_pbh_hash_count(0)

            # PBH hash field
            pbhlogger.info("Remove PBH hash field: {}".format(PBH_HASH_FIELD_NAME))
            dvs_pbh.remove_pbh_hash_field(PBH_HASH_FIELD_NAME)
            dvs_pbh.verify_pbh_hash_field_count(0)

    def test_PbhTableCreationDeletion(self, testlog, dvs_pbh, dvs_acl):
        try:
            pbhlogger.info("Create PBH table: {}".format(PBH_TABLE_NAME))
            dvs_pbh.create_pbh_table(
                table_name=PBH_TABLE_NAME,
                interface_list=PBH_TABLE_INTERFACE_LIST,
                description=PBH_TABLE_DESCRIPTION
            )
            dvs_acl.verify_acl_table_count(1)
        finally:
            pbhlogger.info("Remove PBH table: {}".format(PBH_TABLE_NAME))
            dvs_pbh.remove_pbh_table(PBH_TABLE_NAME)
            dvs_acl.verify_acl_table_count(0)

    def test_PbhRuleCreationDeletion(self, testlog, dvs_pbh, dvs_acl):
        try:
            # PBH hash field
            pbhlogger.info("Create PBH hash field: {}".format(PBH_HASH_FIELD_NAME))
            dvs_pbh.create_pbh_hash_field(
                hash_field_name=PBH_HASH_FIELD_NAME,
                hash_field=PBH_HASH_FIELD_HASH_FIELD,
                sequence_id=PBH_HASH_FIELD_SEQUENCE_ID
            )
            dvs_pbh.verify_pbh_hash_field_count(1)

            # PBH hash
            pbhlogger.info("Create PBH hash: {}".format(PBH_HASH_NAME))
            dvs_pbh.create_pbh_hash(
                hash_name=PBH_HASH_NAME,
                hash_field_list=PBH_HASH_HASH_FIELD_LIST
            )
            dvs_pbh.verify_pbh_hash_count(1)

            # PBH table
            pbhlogger.info("Create PBH table: {}".format(PBH_TABLE_NAME))
            dvs_pbh.create_pbh_table(
                table_name=PBH_TABLE_NAME,
                interface_list=PBH_TABLE_INTERFACE_LIST,
                description=PBH_TABLE_DESCRIPTION
            )
            dvs_acl.verify_acl_table_count(1)

            # PBH rule
            attr_list = {
                "gre_key": PBH_RULE_GRE_KEY,
                "inner_ether_type": PBH_RULE_INNER_ETHER_TYPE
            }

            pbhlogger.info("Create PBH rule: {}".format(PBH_RULE_NAME))
            dvs_pbh.create_pbh_rule(
                table_name=PBH_TABLE_NAME,
                rule_name=PBH_RULE_NAME,
                priority=PBH_RULE_PRIORITY,
                qualifiers=attr_list,
                hash_name=PBH_RULE_HASH
            )
            dvs_acl.verify_acl_rule_count(1)
        finally:
            # PBH rule
            pbhlogger.info("Remove PBH rule: {}".format(PBH_RULE_NAME))
            dvs_pbh.remove_pbh_rule(PBH_TABLE_NAME, PBH_RULE_NAME)
            dvs_acl.verify_acl_rule_count(0)

            # PBH table
            pbhlogger.info("Remove PBH table: {}".format(PBH_TABLE_NAME))
            dvs_pbh.remove_pbh_table(PBH_TABLE_NAME)
            dvs_acl.verify_acl_table_count(0)

            # PBH hash
            pbhlogger.info("Remove PBH hash: {}".format(PBH_HASH_NAME))
            dvs_pbh.remove_pbh_hash(PBH_HASH_NAME)
            dvs_pbh.verify_pbh_hash_count(0)

            # PBH hash field
            pbhlogger.info("Remove PBH hash field: {}".format(PBH_HASH_FIELD_NAME))
            dvs_pbh.remove_pbh_hash_field(PBH_HASH_FIELD_NAME)
            dvs_pbh.verify_pbh_hash_field_count(0)


@pytest.mark.usefixtures("dvs_lag_manager")
class TestPbhExtendedFlows:
    class PbhRefCountHelper(object):
        def __init__(self):
            self.hashFieldCount = 0
            self.hashCount = 0
            self.ruleCount = 0
            self.tableCount = 0

        def incPbhHashFieldCount(self):
            self.hashFieldCount += 1

        def decPbhHashFieldCount(self):
            self.hashFieldCount -= 1

        def getPbhHashFieldCount(self):
            return self.hashFieldCount

        def incPbhHashCount(self):
            self.hashCount += 1

        def decPbhHashCount(self):
            self.hashCount -= 1

        def getPbhHashCount(self):
            return self.hashCount

        def incPbhRuleCount(self):
            self.ruleCount += 1

        def decPbhRuleCount(self):
            self.ruleCount -= 1

        def getPbhRuleCount(self):
            return self.ruleCount

        def incPbhTableCount(self):
            self.tableCount += 1

        def decPbhTableCount(self):
            self.tableCount -= 1

        def getPbhTableCount(self):
            return self.tableCount

    class LagRefCountHelper(object):
        def __init__(self):
            self.lagCount = 0
            self.lagMemberCount = 0

        def incLagCount(self):
            self.lagCount += 1

        def decLagCount(self):
            self.lagCount -= 1

        def getLagCount(self):
            return self.lagCount

        def incLagMemberCount(self):
            self.lagMemberCount += 1

        def decLagMemberCount(self):
            self.lagMemberCount -= 1

        def getLagMemberCount(self):
            return self.lagMemberCount

    def strip_prefix(self, s, p):
        return s[len(p):] if s.startswith(p) else s

    @pytest.fixture(autouse=True)
    def pbh_ref_count(self):
        pbhlogger.info("Create PBH reference count helper")
        yield self.PbhRefCountHelper()
        pbhlogger.info("Remove PBH reference count helper")

    @pytest.fixture(autouse=True)
    def lag_ref_count(self):
        pbhlogger.info("Create LAG reference count helper")
        yield self.LagRefCountHelper()
        pbhlogger.info("Remove LAG reference count helper")

    @pytest.fixture(autouse=True)
    def pbh_port_channel_0001(self, lag_ref_count):
        try:
            meta_dict = {
                "name": "PortChannel0001",
                "member": "Ethernet120"
            }

            lag_id = self.strip_prefix(meta_dict["name"], "PortChannel")

            pbhlogger.info("Create LAG: {}".format(meta_dict["name"]))
            self.dvs_lag.create_port_channel(lag_id)
            lag_ref_count.incLagCount()
            self.dvs_lag.get_and_verify_port_channel(lag_ref_count.getLagCount())

            pbhlogger.info("Create LAG member: {}".format(meta_dict["member"]))
            self.dvs_lag.create_port_channel_member(lag_id, meta_dict["member"])
            lag_ref_count.incLagMemberCount()
            self.dvs_lag.get_and_verify_port_channel_members(lag_ref_count.getLagMemberCount())

            yield meta_dict

        finally:
            pbhlogger.info("Remove LAG member: {}".format(meta_dict["member"]))
            self.dvs_lag.remove_port_channel_member(lag_id, meta_dict["member"])
            lag_ref_count.decLagMemberCount()
            self.dvs_lag.get_and_verify_port_channel_members(lag_ref_count.getLagMemberCount())

            pbhlogger.info("Remove LAG: {}".format(meta_dict["name"]))
            self.dvs_lag.remove_port_channel(lag_id)
            lag_ref_count.decLagCount()
            self.dvs_lag.get_and_verify_port_channel(lag_ref_count.getLagCount())

    @pytest.fixture(autouse=True)
    def pbh_port_channel_0002(self, lag_ref_count):
        try:
            meta_dict = {
                "name": "PortChannel0002",
                "member": "Ethernet124"
            }

            lag_id = self.strip_prefix(meta_dict["name"], "PortChannel")

            pbhlogger.info("Create LAG: {}".format(meta_dict["name"]))
            self.dvs_lag.create_port_channel(lag_id)
            lag_ref_count.incLagCount()
            self.dvs_lag.get_and_verify_port_channel(lag_ref_count.getLagCount())

            pbhlogger.info("Create LAG member: {}".format(meta_dict["member"]))
            self.dvs_lag.create_port_channel_member(lag_id, meta_dict["member"])
            lag_ref_count.incLagMemberCount()
            self.dvs_lag.get_and_verify_port_channel_members(lag_ref_count.getLagMemberCount())

            yield meta_dict

        finally:
            pbhlogger.info("Remove LAG member: {}".format(meta_dict["member"]))
            self.dvs_lag.remove_port_channel_member(lag_id, meta_dict["member"])
            lag_ref_count.decLagMemberCount()
            self.dvs_lag.get_and_verify_port_channel_members(lag_ref_count.getLagMemberCount())

            pbhlogger.info("Remove LAG: {}".format(meta_dict["name"]))
            self.dvs_lag.remove_port_channel(lag_id)
            lag_ref_count.decLagCount()
            self.dvs_lag.get_and_verify_port_channel(lag_ref_count.getLagCount())

    @pytest.fixture
    def pbh_inner_ip_proto(self, dvs_pbh, pbh_ref_count):
        try:
            meta_dict = {
                "name": "inner_ip_proto",
                "hash_field": "INNER_IP_PROTOCOL",
                "sequence_id": "1"
            }

            pbhlogger.info("Create PBH hash field: {}".format(meta_dict["name"]))
            dvs_pbh.create_pbh_hash_field(
                hash_field_name=meta_dict["name"],
                hash_field=meta_dict["hash_field"],
                sequence_id=meta_dict["sequence_id"]
            )
            pbh_ref_count.incPbhHashFieldCount()
            dvs_pbh.verify_pbh_hash_field_count(pbh_ref_count.getPbhHashFieldCount())

            yield meta_dict

        finally:
            pbhlogger.info("Remove PBH hash field: {}".format(meta_dict["name"]))
            dvs_pbh.remove_pbh_hash_field(meta_dict["name"])
            pbh_ref_count.decPbhHashFieldCount()
            dvs_pbh.verify_pbh_hash_field_count(pbh_ref_count.getPbhHashFieldCount())

    @pytest.fixture
    def pbh_inner_l4_dst_port(self, dvs_pbh, pbh_ref_count):
        try:
            meta_dict = {
                "name": "inner_l4_dst_port",
                "hash_field": "INNER_L4_DST_PORT",
                "sequence_id": "2"
            }

            pbhlogger.info("Create PBH hash field: {}".format(meta_dict["name"]))
            dvs_pbh.create_pbh_hash_field(
                hash_field_name=meta_dict["name"],
                hash_field=meta_dict["hash_field"],
                sequence_id=meta_dict["sequence_id"]
            )
            pbh_ref_count.incPbhHashFieldCount()
            dvs_pbh.verify_pbh_hash_field_count(pbh_ref_count.getPbhHashFieldCount())

            yield meta_dict

        finally:
            pbhlogger.info("Remove PBH hash field: {}".format(meta_dict["name"]))
            dvs_pbh.remove_pbh_hash_field(meta_dict["name"])
            pbh_ref_count.decPbhHashFieldCount()
            dvs_pbh.verify_pbh_hash_field_count(pbh_ref_count.getPbhHashFieldCount())

    @pytest.fixture
    def pbh_inner_l4_src_port(self, dvs_pbh, pbh_ref_count):
        try:
            meta_dict = {
                "name": "inner_l4_src_port",
                "hash_field": "INNER_L4_SRC_PORT",
                "sequence_id": "2"
            }

            pbhlogger.info("Create PBH hash field: {}".format(meta_dict["name"]))
            dvs_pbh.create_pbh_hash_field(
                hash_field_name=meta_dict["name"],
                hash_field=meta_dict["hash_field"],
                sequence_id=meta_dict["sequence_id"]
            )
            pbh_ref_count.incPbhHashFieldCount()
            dvs_pbh.verify_pbh_hash_field_count(pbh_ref_count.getPbhHashFieldCount())

            yield meta_dict

        finally:
            pbhlogger.info("Remove PBH hash field: {}".format(meta_dict["name"]))
            dvs_pbh.remove_pbh_hash_field(meta_dict["name"])
            pbh_ref_count.decPbhHashFieldCount()
            dvs_pbh.verify_pbh_hash_field_count(pbh_ref_count.getPbhHashFieldCount())

    @pytest.fixture
    def pbh_inner_dst_ipv4(self, dvs_pbh, pbh_ref_count):
        try:
            meta_dict = {
                "name": "inner_dst_ipv4",
                "hash_field": "INNER_DST_IPV4",
                "ip_mask": "255.0.0.0",
                "sequence_id": "3"
            }

            pbhlogger.info("Create PBH hash field: {}".format(meta_dict["name"]))
            dvs_pbh.create_pbh_hash_field(
                hash_field_name=meta_dict["name"],
                hash_field=meta_dict["hash_field"],
                ip_mask=meta_dict["ip_mask"],
                sequence_id=meta_dict["sequence_id"]
            )
            pbh_ref_count.incPbhHashFieldCount()
            dvs_pbh.verify_pbh_hash_field_count(pbh_ref_count.getPbhHashFieldCount())

            yield meta_dict

        finally:
            pbhlogger.info("Remove PBH hash field: {}".format(meta_dict["name"]))
            dvs_pbh.remove_pbh_hash_field(meta_dict["name"])
            pbh_ref_count.decPbhHashFieldCount()
            dvs_pbh.verify_pbh_hash_field_count(pbh_ref_count.getPbhHashFieldCount())

    @pytest.fixture
    def pbh_inner_src_ipv4(self, dvs_pbh, pbh_ref_count):
        try:
            meta_dict = {
                "name": "inner_src_ipv4",
                "hash_field": "INNER_SRC_IPV4",
                "ip_mask": "0.0.0.255",
                "sequence_id": "3"
            }

            pbhlogger.info("Create PBH hash field: {}".format(meta_dict["name"]))
            dvs_pbh.create_pbh_hash_field(
                hash_field_name=meta_dict["name"],
                hash_field=meta_dict["hash_field"],
                ip_mask=meta_dict["ip_mask"],
                sequence_id=meta_dict["sequence_id"]
            )
            pbh_ref_count.incPbhHashFieldCount()
            dvs_pbh.verify_pbh_hash_field_count(pbh_ref_count.getPbhHashFieldCount())

            yield meta_dict

        finally:
            pbhlogger.info("Remove PBH hash field: {}".format(meta_dict["name"]))
            dvs_pbh.remove_pbh_hash_field(meta_dict["name"])
            pbh_ref_count.decPbhHashFieldCount()
            dvs_pbh.verify_pbh_hash_field_count(pbh_ref_count.getPbhHashFieldCount())

    @pytest.fixture
    def pbh_inner_dst_ipv6(self, dvs_pbh, pbh_ref_count):
        try:
            meta_dict = {
                "name": "inner_dst_ipv6",
                "hash_field": "INNER_DST_IPV6",
                "ip_mask": "ffff::",
                "sequence_id": "4"
            }

            pbhlogger.info("Create PBH hash field: {}".format(meta_dict["name"]))
            dvs_pbh.create_pbh_hash_field(
                hash_field_name=meta_dict["name"],
                hash_field=meta_dict["hash_field"],
                ip_mask=meta_dict["ip_mask"],
                sequence_id=meta_dict["sequence_id"]
            )
            pbh_ref_count.incPbhHashFieldCount()
            dvs_pbh.verify_pbh_hash_field_count(pbh_ref_count.getPbhHashFieldCount())

            yield meta_dict

        finally:
            pbhlogger.info("Remove PBH hash field: {}".format(meta_dict["name"]))
            dvs_pbh.remove_pbh_hash_field(meta_dict["name"])
            pbh_ref_count.decPbhHashFieldCount()
            dvs_pbh.verify_pbh_hash_field_count(pbh_ref_count.getPbhHashFieldCount())

    @pytest.fixture
    def pbh_inner_src_ipv6(self, dvs_pbh, pbh_ref_count):
        try:
            meta_dict = {
                "name": "inner_src_ipv6",
                "hash_field": "INNER_SRC_IPV6",
                "ip_mask": "::ffff",
                "sequence_id": "4"
            }

            pbhlogger.info("Create PBH hash field: {}".format(meta_dict["name"]))
            dvs_pbh.create_pbh_hash_field(
                hash_field_name=meta_dict["name"],
                hash_field=meta_dict["hash_field"],
                ip_mask=meta_dict["ip_mask"],
                sequence_id=meta_dict["sequence_id"]
            )
            pbh_ref_count.incPbhHashFieldCount()
            dvs_pbh.verify_pbh_hash_field_count(pbh_ref_count.getPbhHashFieldCount())

            yield meta_dict

        finally:
            pbhlogger.info("Remove PBH hash field: {}".format(meta_dict["name"]))
            dvs_pbh.remove_pbh_hash_field(meta_dict["name"])
            pbh_ref_count.decPbhHashFieldCount()
            dvs_pbh.verify_pbh_hash_field_count(pbh_ref_count.getPbhHashFieldCount())

    @pytest.fixture
    def pbh_inner_v4(
        self,
        dvs_pbh,
        pbh_ref_count,
        pbh_inner_ip_proto,
        pbh_inner_l4_dst_port,
        pbh_inner_l4_src_port,
        pbh_inner_dst_ipv4,
        pbh_inner_src_ipv4
    ):
        try:
            meta_dict = {
                "name": "inner_v4_hash",
                "hash_field_list": [
                    pbh_inner_ip_proto["name"],
                    pbh_inner_l4_dst_port["name"],
                    pbh_inner_l4_src_port["name"],
                    pbh_inner_dst_ipv4["name"],
                    pbh_inner_src_ipv4["name"]
                ]
            }

            pbhlogger.info("Create PBH hash: {}".format(meta_dict["name"]))
            dvs_pbh.create_pbh_hash(
                hash_name=meta_dict["name"],
                hash_field_list=meta_dict["hash_field_list"]
            )
            pbh_ref_count.incPbhHashCount()
            dvs_pbh.verify_pbh_hash_count(pbh_ref_count.getPbhHashCount())

            yield meta_dict

        finally:
            pbhlogger.info("Remove PBH hash: {}".format(meta_dict["name"]))
            dvs_pbh.remove_pbh_hash(meta_dict["name"])
            pbh_ref_count.decPbhHashCount()
            dvs_pbh.verify_pbh_hash_count(pbh_ref_count.getPbhHashCount())

    @pytest.fixture
    def pbh_inner_v6(
        self,
        dvs_pbh,
        pbh_ref_count,
        pbh_inner_ip_proto,
        pbh_inner_l4_dst_port,
        pbh_inner_l4_src_port,
        pbh_inner_dst_ipv6,
        pbh_inner_src_ipv6
    ):
        try:
            meta_dict = {
                "name": "inner_v6_hash",
                "hash_field_list": [
                    pbh_inner_ip_proto["name"],
                    pbh_inner_l4_dst_port["name"],
                    pbh_inner_l4_src_port["name"],
                    pbh_inner_dst_ipv6["name"],
                    pbh_inner_src_ipv6["name"]
                ]
            }

            pbhlogger.info("Create PBH hash: {}".format(meta_dict["name"]))
            dvs_pbh.create_pbh_hash(
                hash_name=meta_dict["name"],
                hash_field_list=meta_dict["hash_field_list"]
            )
            pbh_ref_count.incPbhHashCount()
            dvs_pbh.verify_pbh_hash_count(pbh_ref_count.getPbhHashCount())

            yield meta_dict

        finally:
            pbhlogger.info("Remove PBH hash: {}".format(meta_dict["name"]))
            dvs_pbh.remove_pbh_hash(meta_dict["name"])
            pbh_ref_count.decPbhHashCount()
            dvs_pbh.verify_pbh_hash_count(pbh_ref_count.getPbhHashCount())

    @pytest.fixture
    def pbh_table(
        self,
        dvs_pbh,
        dvs_acl,
        pbh_ref_count,
        pbh_port_channel_0001,
        pbh_port_channel_0002
    ):
        try:
            meta_dict = {
                "name": "pbh_table",
                "interface_list": [
                    "Ethernet0",
                    "Ethernet4",
                    pbh_port_channel_0001["name"],
                    pbh_port_channel_0002["name"]
                ],
                "description": "NVGRE and VxLAN"
            }

            pbhlogger.info("Create PBH table: {}".format(meta_dict["name"]))
            dvs_pbh.create_pbh_table(
                table_name=meta_dict["name"],
                interface_list=meta_dict["interface_list"],
                description=meta_dict["description"]
            )
            pbh_ref_count.incPbhTableCount()
            dvs_acl.verify_acl_table_count(pbh_ref_count.getPbhTableCount())

            yield meta_dict

        finally:
            pbhlogger.info("Remove PBH table: {}".format(meta_dict["name"]))
            dvs_pbh.remove_pbh_table(meta_dict["name"])
            pbh_ref_count.decPbhTableCount()
            dvs_acl.verify_acl_table_count(pbh_ref_count.getPbhTableCount())

    @pytest.fixture
    def pbh_nvgre(
        self,
        dvs_pbh,
        dvs_acl,
        pbh_ref_count,
        pbh_table,
        pbh_inner_v6
    ):
        try:
            meta_dict = {
                "table": pbh_table["name"],
                "name": "nvgre",
                "priority": "1",
                "gre_key": "0x2500/0xffffff00",
                "inner_ether_type": "0x86dd/0xffff",
                "hash": pbh_inner_v6["name"],
                "packet_action": "SET_ECMP_HASH",
                "flow_counter": "DISABLED"
            }

            attr_list = {
                "gre_key": meta_dict["gre_key"],
                "inner_ether_type": meta_dict["inner_ether_type"]
            }

            pbhlogger.info("Create PBH rule: {}".format(meta_dict["name"]))
            dvs_pbh.create_pbh_rule(
                table_name=meta_dict["table"],
                rule_name=meta_dict["name"],
                priority=meta_dict["priority"],
                qualifiers=attr_list,
                hash_name=meta_dict["hash"],
                packet_action=meta_dict["packet_action"],
                flow_counter=meta_dict["flow_counter"],
            )
            pbh_ref_count.incPbhRuleCount()
            dvs_acl.verify_acl_rule_count(pbh_ref_count.getPbhRuleCount())

            yield meta_dict

        finally:
            pbhlogger.info("Remove PBH rule: {}".format(meta_dict["name"]))
            dvs_pbh.remove_pbh_rule(meta_dict["table"], meta_dict["name"])
            pbh_ref_count.decPbhRuleCount()
            dvs_acl.verify_acl_rule_count(pbh_ref_count.getPbhRuleCount())

    @pytest.fixture
    def pbh_vxlan(
        self,
        dvs_pbh,
        dvs_acl,
        pbh_ref_count,
        pbh_table,
        pbh_inner_v4
    ):
        try:
            meta_dict = {
                "table": pbh_table["name"],
                "name": "vxlan",
                "priority": "2",
                "ip_protocol": "0x11/0xff",
                "l4_dst_port": "0x12b5/0xffff",
                "inner_ether_type": "0x0800/0xffff",
                "hash": pbh_inner_v4["name"],
                "packet_action": "SET_LAG_HASH",
                "flow_counter": "ENABLED"
            }

            attr_list = {
                "ip_protocol": meta_dict["ip_protocol"],
                "l4_dst_port": meta_dict["l4_dst_port"],
                "inner_ether_type": meta_dict["inner_ether_type"]
            }

            pbhlogger.info("Create PBH rule: {}".format(meta_dict["name"]))
            dvs_pbh.create_pbh_rule(
                table_name=meta_dict["table"],
                rule_name=meta_dict["name"],
                priority=meta_dict["priority"],
                qualifiers=attr_list,
                hash_name=meta_dict["hash"],
                packet_action=meta_dict["packet_action"],
                flow_counter=meta_dict["flow_counter"],
            )
            pbh_ref_count.incPbhRuleCount()
            dvs_acl.verify_acl_rule_count(pbh_ref_count.getPbhRuleCount())

            yield meta_dict

        finally:
            pbhlogger.info("Remove PBH rule: {}".format(meta_dict["name"]))
            dvs_pbh.remove_pbh_rule(meta_dict["table"], meta_dict["name"])
            pbh_ref_count.decPbhRuleCount()
            dvs_acl.verify_acl_rule_count(pbh_ref_count.getPbhRuleCount())

    def test_PbhNvgreVxlanConfiguration(self, testlog, pbh_nvgre, pbh_vxlan):
        pass


# Add Dummy always-pass test at end as workaroud
# for issue when Flaky fail on final test it invokes module tear-down before retrying
def test_nonflaky_dummy():
    pass
