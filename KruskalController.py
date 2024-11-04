import copy
import warnings
from random import randint

import matplotlib.pyplot as plt
import networkx as nx
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import ether_types, ethernet, packet
from ryu.ofproto import ofproto_v1_3
from ryu.topology import event
from ryu.topology.api import get_link, get_switch


class UnionFindSet:
    def __init__(self, n: int) -> None:
        self.fa = [i for i in range(n + 1)]
        self.size = n

    def find(self, x: int) -> int:
        if self.fa[x] != x:
            self.fa[x] = self.find(self.fa[x])
        return self.fa[x]

    def union(self, x: int, y: int) -> None:
        x = self.find(x)
        y = self.find(y)
        if x != y:
            self.fa[y] = x


class Topo(nx.DiGraph):
    def __init__(self):
        super().__init__()
        warnings.filterwarnings("ignore", category=UserWarning)
        self.set = None
        self.MST_exist = False
        self.plot_options = {
            "font_size": 20,
            "node_size": 1500,
            "node_color": "white",
            "linewidths": 3,
            "width": 3,
            "with_labels": True
        }
        self.pos = nx.spring_layout(self)
        plt.figure(1, figsize=(18, 14))
        plt.ion()

    def initialize_ufset(self, n: int):
        """Initialize Union-Find set based on the number of nodes."""
        self.set = UnionFindSet(n)

    def Kruskal(self) -> list:
        tree_edges = []
        for e in sorted(self.edges(data=True), key=lambda e: e[2]["weight"]):
            if self.set.find(e[0]) != self.set.find(e[1]):
                self.set.union(e[0], e[1])
                tree_edges.append((e[0], e[1]))
        self.draw_tree(tree_edges)
        return tree_edges

    def draw_tree(self, tree: list):
        plt.clf()
        plt.title("Minimum Spanning Tree")
        edge_colors = ["red" if (e[0], e[1]) in tree or (e[1], e[0]) in tree else "black" for e in self.edges(data=True)]
        edge_labels = {e[0:2]: e[2]["weight"] for e in self.edges(data=True)}
        node_edge_colors = ["red" if len(tree) else "black"] * len(self.nodes)

        nx.draw(self, pos=self.pos, edge_color=edge_colors, edgecolors=node_edge_colors, **self.plot_options)
        nx.draw_networkx_edge_labels(self, pos=self.pos, edge_labels=edge_labels)
        plt.show()
        plt.pause(1)


class KruskalController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.datapaths = []
        self.mac_to_port = {}
        self.topo = Topo()

    def find_datapath_by_id(self, dpid: int):
        for datapath in self.datapaths:
            if datapath.id == dpid:
                return datapath
        return None

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id or ofproto.OFP_NO_BUFFER,
                                priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    def send_port_mod(self, datapath, port_no, opt):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser

        hw_addr = next((p.hw_addr for p in get_switch(self, dpid=datapath.id)[0].ports if p.port_no == port_no), None)
        if hw_addr is None:
            return

        config = opt
        mask_all = ofp.OFPPC_PORT_DOWN | ofp.OFPPC_NO_RECV | ofp.OFPPC_NO_FWD | ofp.OFPPC_NO_PACKET_IN
        req = ofp_parser.OFPPortMod(datapath=datapath, port_no=port_no, hw_addr=hw_addr, config=config, mask=mask_all)
        datapath.send_msg(req)

    def block_links(self, excepts: list):
        for e in self.topo.edges(data=True):
            if (e[0], e[1]) in excepts or (e[1], e[0]) in excepts:
                continue
            src_dp, dst_dp = self.find_datapath_by_id(e[0]), self.find_datapath_by_id(e[1])
            if src_dp and dst_dp:
                self.send_port_mod(src_dp, e[2]["src_port"], src_dp.ofproto.OFPPC_PORT_DOWN)
                self.send_port_mod(dst_dp, e[2]["dst_port"], dst_dp.ofproto.OFPPC_PORT_DOWN)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, event):
        msg, datapath, in_port = event.msg, event.msg.datapath, event.msg.match['in_port']
        parser, ofproto, dpid = datapath.ofproto_parser, datapath.ofproto, datapath.id
        pkt, eth = packet.Packet(msg.data), packet.Packet(msg.data).get_protocol(ethernet.ethernet)

        if eth.ethertype in (ether_types.ETH_TYPE_LLDP, ether_types.ETH_TYPE_IPV6):
            return

        dst_mac, src_mac = eth.dst, eth.src
        self.mac_to_port.setdefault(dpid, {})[src_mac] = in_port
        out_port = self.mac_to_port[dpid].get(dst_mac, ofproto.OFPP_FLOOD)

        if out_port == ofproto.OFPP_FLOOD and not self.topo.MST_exist:
            tree_edges = self.topo.Kruskal()
            self.block_links(tree_edges)
            self.topo.MST_exist = True

        actions = [parser.OFPActionOutput(out_port)]
        match = parser.OFPMatch(in_port=in_port, eth_dst=dst_mac, eth_src=src_mac)
        self.add_flow(datapath, 1, match, actions, msg.buffer_id or ofproto.OFP_NO_BUFFER)

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, event):
        self.topo = Topo()
        self.topo.clear()
        all_switches, all_links = copy.copy(get_switch(self)), copy.copy(get_link(self))
        self.datapaths = [s.dp for s in all_switches]
        self.topo.add_nodes_from([(s.dp.id, {"ports": [p.port_no for p in s.ports]}) for s in all_switches])
        self.topo.initialize_ufset(len(all_switches))
        for link in all_links:
            u, v = link.src.dpid, link.dst.dpid
            weight = self.topo.edges[v, u]['weight'] if self.topo.has_edge(v, u) else randint(1, 10)
            self.topo.add_edge(u, v, src_port=link.src.port_no, dst_port=link.dst.port_no, weight=weight)

        edge_labels = {e[0:2]: e[2]["weight"] for e in self.topo.edges(data=True)}
        nx.draw(self.topo, pos=self.topo.pos, edgecolors="black", **self.topo.plot_options)
        nx.draw_networkx_edge_labels(self.topo, pos=self.topo.pos, edge_labels=edge_labels)
        plt.show()
       
