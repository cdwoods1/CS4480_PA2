from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ether_types


# Class that is the controller for the simple load balancer switch.
class LoadBalancerSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    #Constants to keep track of specified IPs, MAC addresses, and ports
    VIRTUAL_IP = '10.0.0.10'

    SERVER_IP_ONE   = '10.0.0.1'
    SERVER_IP_TWO   = '10.0.0.2'
    SERVER_IP_THREE = '10.0.0.3'
    SERVER_IP_FOUR  = '10.0.0.4'
    SERVER_IP_FIVE  = '10.0.0.5'
    SERVER_IP_SIX   = '10.0.0.6'

    MAC_ONE   = '00:00:00:00:00:01'
    MAC_TWO   = '00:00:00:00:00:02'
    MAC_THREE = '00:00:00:00:00:03'
    MAC_FOUR  = '00:00:00:00:00:04'
    MAC_FIVE  = '00:00:00:00:00:05'
    MAC_SIX   = '00:00:00:00:00:06'

    PORT_FIVE = 5;
    PORT_SIX = 6;

    CURRENT_IP = "10.0.0.5"
    CURRENT_MAC = "00:00:00:00:00:05"
    CURRENT_PORT = 5

    #Method that changes the current server being mapped to.
    def change_server(self):
        if self.CURRENT_IP == "10.0.0.5":
            self.CURRENT_IP = "10.0.0.6"
            self.CURRENT_MAC = "00:00:00:00:00:06"
            self.CURRENT_PORT = 6
        else:
            self.CURRENT_IP = "10.0.0.5"
            self.CURRENT_MAC = "00:00:00:00:00:05"
            self.CURRENT_PORT = 5


    #Initializer
    def __init__(self, *args, **kwargs):
        super(LoadBalancerSwitch, self).__init__(*args, **kwargs)
        CURRENT_IP = "10.0.0.5"
        CURRENT_MAC = "00:00:00:00:00:05"
        CURRENT_PORT = 5
        self.mac_to_port = {}

    #Method that adds a new flew based off of the given match and action.
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]

        mod = parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=inst,
                                buffer_id=ofproto.OFP_NO_BUFFER)

        datapath.send_msg(mod)

    #Method that handles any new packets given.
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        #Only handles ARP type packets.
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arpp = pkt.get_protocols(arp.arp)[0]
            src_ip = arpp.src_ip
            #Installs flows in both directions using the appropriate match and action.
            if src_ip != self.SERVER_IP_SIX and src_ip != self.SERVER_IP_FIVE:
                match = parser.OFPMatch(in_port=in_port, ipv4_dst=self.VIRTUAL_IP, eth_type=0x0800)
                actions = [parser.OFPActionSetField(ipv4_dst=self.CURRENT_IP), parser.OFPActionOutput(self.CURRENT_PORT)]
                self.add_flow(datapath, 1, match, actions)

                match = parser.OFPMatch(in_port=self.CURRENT_PORT, ipv4_src=self.CURRENT_IP, ipv4_dst=src_ip, eth_type=0x0800)
                actions = [parser.OFPActionSetField(ipv4_src=self.VIRTUAL_IP), parser.OFPActionOutput(in_port)]
                self.add_flow(datapath, 1, match, actions)
            self.get_arp_reply(datapath, pkt, eth, parser, ofproto, in_port)
            if src_ip != self.SERVER_IP_SIX and src_ip != self.SERVER_IP_FIVE:
                self.change_server()
            return
        else:
            return

    #Creates and sends the appropriate ARP reply packet.
    def get_arp_reply(self, datapath, pkt, eth, parser, ofproto, in_port):
        arp_pkt = pkt.get_protocol(arp.arp)
        dst_ip = arp_pkt.src_ip
        src_ip = arp_pkt.dst_ip
        dst_mac = eth.src

        #Determines which MAC address to send.
        if dst_ip != self.SERVER_IP_SIX and dst_ip != self.SERVER_IP_FIVE:
            src_mac = self.CURRENT_MAC
        else:
            if src_ip == self.SERVER_IP_ONE:
                src_mac = self.MAC_ONE
            elif src_ip == self.SERVER_IP_TWO:
                src_mac = self.MAC_TWO
            elif src_ip == self.SERVER_IP_THREE:
                src_mac = self.MAC_THREE
            elif src_ip == self.SERVER_IP_FOUR:
                src_mac = self.MAC_FOUR
            else:
                return
        #Creates the packet, adds the protocol, and sends the packet out.
        e = ethernet.ethernet(dst_mac, src_mac, ether_types.ETH_TYPE_ARP)
        a = arp.arp(1, 0x0800, 6, 4, 2, src_mac, src_ip, dst_mac, dst_ip)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()

        actions = [parser.OFPActionOutput(ofproto.OFPP_IN_PORT)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=in_port, actions=actions, data=p.data)
        datapath.send_msg(out)

