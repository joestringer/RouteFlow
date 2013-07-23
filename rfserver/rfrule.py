import logging
from rflib.ipc.RFProtocol import RouteMod
from rflib.types.Match import *
from rflib.types.Action import *
from rflib.types.Option import *
from rflib.util import load_from_dict, pack_into_dict

priorities = [PRIORITY_LOWEST, PRIORITY_LOW, PRIORITY_HIGH,
              PRIORITY_HIGHEST]
pindex = ["lowest", "low", "high", "highest"]

_logger = logging.getLogger(__name__)


class RFRuleEntry:
    def __init__(self, name="", priority=None, vs_only=None, routemod=None):
        self.id = None
        self.name = name
        self.priority = priority
        self.vs_only = vs_only
        self.routemod = routemod

    def __str__(self):
        return "priority: %s vs-only: %s routemod: %s"\
                % (str(self.priority), str(self.vs_only), str(self.routemod))

    def from_dict(self, data):
        for k, v in data.items():
            if str(v) is "":
                data[k] = None
            elif k == "priority":
                data[k] = int(v)
            elif k == "vs_only":
                data[k] = bool(v)
        self.id = data["_id"]
        load_from_dict(data, self, "name")
        load_from_dict(data, self, "priority")
        load_from_dict(data, self, "vs_only")
        load_from_dict(data, self, "routemod")

    def to_dict(self):
        data = {}
        if self.id is not None:
            data["_id"] = self.id
        pack_into_dict(data, self, "name")
        pack_into_dict(data, self, "priority")
        pack_into_dict(data, self, "vs_only")
        pack_into_dict(data, self, "routemod")
        return data


def create_base_routemod(rule, priority):
    rm = RouteMod(RMT_ADD)

    rm.add_option(Option.PRIORITY(priority))
    if rule["destination"] == "controller":
        rm.add_action(Action.CONTROLLER())
    else:  # No action means "drop"
        pass
    return rm


def parse_l2(rule, flows):
    _logger.debug("Parsing L2")
    try:
        addr = rule["match"]["dl-addr"]
        for rm in flows:
            rm.add_match(Match.ETHERNET(addr))
        _logger.debug("Parsed dl-addr: %s" % (addr))
    except KeyError:
        pass
    try:
        ethertypes = [ int(eth, 16) for eth in rule["match"]["dl-type"] ]
        flows2 = []
        for eth in ethertypes:
            for flow in flows:
                new = RouteMod()
                new.from_dict(flow.to_dict())
                new.add_match(Match.ETHERTYPE(eth))
                flows2.append(new)
            _logger.debug("Parsed dl-type: %s" % (eth))
        flows = flows2
    except KeyError:
        pass
    return flows


def parse_l3(rule, flows):
    _logger.debug("Parsing L3")
    try:
        addr = rule["match"]["nw-addr"]
        ip_type = Match.IPV4
        prefix = IPV4_MASK_EXACT
        if ":" in addr:
            ip_type = Match.IPV6
            prefix = IPV6_MASK_EXACT
        for rm in flows:
            rm.add_match(ip_type(addr, prefix))
        _logger.debug("Parsed nw-addr: %s" % (addr))
    except KeyError:
        pass
    try:
        proto = rule["match"]["nw-proto"]
        for rm in flows:
            rm.add_match(Match.NW_PROTO(proto))
        _logger.debug("Parsed nw-proto: %s" % (proto))
    except KeyError:
        pass
    return flows


def parse_l4(rule, flows):
    _logger.debug("Parsing L4")
    try:
        port = int(rule["match"]["tp-port"])
        flows2 = []
        for M in [Match.TP_SRC, Match.TP_DST]:
            for flow in flows:
                new = RouteMod()
                new.from_dict(flow.to_dict())
                new.add_match(M(port))
                flows2.append(new)
            _logger.debug("Parsed tp-port: %s" % (port))
        flows = flows2
    except KeyError:
        pass
    return flows


def parse_rule_cfg(config):
    """Parse default flow entries for datapaths.

    This function returns a list of RFRuleEntry objects.

    Keyword arguments:
    config -- A JSON configuration that matches "rfserver/config.schema"
    """
    all_flows = []
    for p, pi in enumerate(pindex):
        try:
            ruleset = config["default-rules"][pi]
        except KeyError:
            continue

        for rule in ruleset:
            flows = []
            name = rule["name"]
            priority = priorities[p]

            _logger.debug("Parsing rule \"%s\"" % (name))

            rm = create_base_routemod(rule, priority)
            flows.append(rm)

            flows = parse_l2(rule, flows)
            flows = parse_l3(rule, flows)
            flows = parse_l4(rule, flows)

            try:
                vs_only = rule["vs-only"]
            except KeyError:
                vs_only = False

            for flow in flows:
                all_flows.append(RFRuleEntry(name, priority, vs_only, flow))

    return all_flows
