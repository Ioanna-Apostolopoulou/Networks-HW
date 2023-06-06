# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
Two OpenFlow 1.0 L3 Static Routers and two OpenFlow 1.0 L2 learning switches.
"""


from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_0
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import arp
from ryu.lib.packet import ipv4
from ryu.lib.packet import icmp
from ryu.lib.packet import ether_types
from ryu.ofproto import inet


"""
fill in the code here (optional)
"""

#Network IP 
left_lan = "192.168.1.0"
right_lan = "192.168.2.0"
mask = 24

#Router IP & MAC address
left_switch_router_ip = "192.168.1.1"
left_switch_router_mac = "00:00:00:00:01:01"
right_switch_router_ip = "192.168.2.1"
right_switch_router_mac = "00:00:00:00:02:01"


#Host IP & MAC address
h1_ip = "192.168.1.2"
h1_mac = "00:00:00:00:01:02"
h2_ip = "192.168.1.3"
h2_mac = "00:00:00:00:01:03"
h3_ip = "192.168.2.2"
h3_mac = "00:00:00:00:02:02"
h4_ip = "192.168.2.3"
h4_mac = "00:00:00:00:02:03"


class SimpleSwitch(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    def add_flow(self, datapath, match, actions):
        ofproto = datapath.ofproto

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)
    
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = msg.datapath_id

        self.logger.info("Datapath ID is %s", hex(dpid))

        if dpid == 0x1A:
            out_port = 4
            match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_src=left_lan, nw_dst=right_lan, nw_dst_mask=mask)
            actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:05:01"),
                        datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:05:02"),
                        datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
            self.add_flow(datapath, match, actions)
        elif dpid == 0x1B:
            out_port = 4
            match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP, nw_src = right_lan, nw_dst=left_lan, nw_dst_mask=mask)
            actions = [datapath.ofproto_parser.OFPActionSetDlSrc("00:00:00:00:05:02"),
                        datapath.ofproto_parser.OFPActionSetDlDst("00:00:00:00:05:01"),
                        datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
            self.add_flow(datapath, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        dst = eth.dst
        src = eth.src
        ethertype = eth.ethertype

        if ethertype == 0x086dd:
            return

        self.mac_to_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s in_port=%s", hex(dpid).ljust(4), hex(ethertype), src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_port[dpid][src] = msg.in_port

        #Left Router
        if dpid == 0x1A:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                """
                fill in the code here
                """
                #Get ARP Protocol Header Elements
                arp_pkt = pkt.get_protocol(arp.arp)

                dst_Ip = arp_pkt.dst_ip
                src_Ip = arp_pkt.src_ip
                dst_Mac = eth.dst
                src_Mac = eth.src


                if dst_Ip == left_switch_router_ip:
                    dst_Mac = eth.src
                    dst_Ip = src_Ip
                    src_Mac = left_switch_router_mac
                    src_Ip = left_switch_router_ip

                elif dst_Ip == right_switch_router_ip:
                    dst_Mac = eth.src
                    dst_Ip = src_Ip
                    src_Mac = right_switch_router_mac
                    src_Ip = right_switch_router_ip

                pkt_reply = packet.Packet()
                pkt_reply.add_protocol(ethernet.ethernet(dst=dst_Mac, 
                                                         src=src_Mac, 
                                                         ethertype=eth.ethertype))
                pkt_reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                               src_mac=src_Mac,
                                               src_ip=src_Ip,
                                               dst_mac=dst_Mac,
                                               dst_ip=dst_Ip))
                pkt_reply.serialize()

                #Send packet out
                actions = [datapath.ofproto_parser.OFPActionOutput(msg.in_port, 0)]
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, 
                                                           buffer_id=ofproto.OFP_NO_BUFFER,
                                                           in_port=datapath.ofproto.OFPP_CONTROLLER, 
                                                           actions=actions, 
                                                           data=pkt_reply.data)
                datapath.send_msg(out)
                print('ARP REPLY SENT')
                #self.logger.info("MY FUCKING packet in %s %s %s %s in_port=%s", hex(dpid), hex(ethertype), src, dst, msg.in_port)
                
                # if arp_pkt.dst_ip == '192.168.1.1' and arp_pkt.dst_mac == '00:00:00:00:04:01':
                #     self.send_arp_reply(datapath, datapath.ofproto_parser, arp_pkt)
                return
            
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                """
                fill in the code here
                """
                #Get IPv4 Protocol Header Elements
                ip_pkt = pkt.get_protocol(ipv4.ipv4)              
                src_Ip = ip_pkt.src
                dst_Ip = ip_pkt.dst

                #Get ICMP Protocol Header Elements
                icmp_pkt = pkt.get_protocol(icmp.icmp)

                #Left Lan Network
                if '192.168.1' in dst_Ip:
                    if dst_Ip == h1_ip:
                        eth_pkt = ethernet.ethernet(dst=h1_mac, src=left_switch_router_mac, ethertype=eth.ethertype)
                        ipv4_pkt = ipv4.ipv4(dst=dst_Ip, src=src_Ip, proto=ip_pkt.proto)
                        icmp_pkt = icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE, csum=0, data=icmp_pkt.data)
                        out_port = 2
                        match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP,nw_src=src_Ip, nw_dst=dst_Ip)
                        actions = [datapath.ofproto_parser.OFPActionSetDlSrc(right_switch_router_mac),
                                datapath.ofproto_parser.OFPActionSetDlDst(h1_mac),
                                datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
                        self.add_flow(datapath, match, actions)
                    elif dst_Ip == h2_ip:
                        eth_pkt = ethernet.ethernet(dst=h2_mac, src=left_switch_router_mac, ethertype=eth.ethertype)
                        ipv4_pkt = ipv4.ipv4(dst=dst_Ip, src=src_Ip, proto=ip_pkt.proto)
                        icmp_pkt = icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE, csum=0, data=icmp_pkt.data)
                        out_port = 2
                        match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP,nw_src=src_Ip, nw_dst=dst_Ip)
                        actions = [datapath.ofproto_parser.OFPActionSetDlSrc(right_switch_router_mac),
                                datapath.ofproto_parser.OFPActionSetDlDst(h2_mac),
                                datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
                        self.add_flow(datapath, match, actions)
                #Right Lan Network
                elif '192.168.2' in dst_Ip:
                    if dst_Ip == h3_ip:
                        eth_pkt = ethernet.ethernet(dst=h3_mac, src=right_switch_router_mac, ethertype=eth.ethertype)
                        ipv4_pkt = ipv4.ipv4(dst=dst_Ip, src=src_Ip, proto=ip_pkt.proto)
                        icmp_pkt = icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE, csum=0, data=icmp_pkt.data)
                        out_port = 1
                        match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP,nw_src=src_Ip, nw_dst=dst_Ip)
                        actions = [datapath.ofproto_parser.OFPActionSetDlSrc(right_switch_router_mac),
                                datapath.ofproto_parser.OFPActionSetDlDst(h3_mac),
                                datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
                        self.add_flow(datapath, match, actions)
                    elif dst_Ip == h4_ip:
                        eth_pkt = ethernet.ethernet(dst=h4_mac, src=right_switch_router_mac, ethertype=eth.ethertype)
                        ipv4_pkt = ipv4.ipv4(dst=dst_Ip, src=src_Ip, proto=ip_pkt.proto)
                        icmp_pkt = icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE, csum=0, data=icmp_pkt.data)
                        out_port = 1
                        match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP,nw_src=src_Ip, nw_dst=dst_Ip)
                        actions = [datapath.ofproto_parser.OFPActionSetDlSrc(right_switch_router_mac),
                                datapath.ofproto_parser.OFPActionSetDlDst(h4_mac),
                                datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
                        self.add_flow(datapath, match, actions)
                # #Unknown IP Destinations Detection
                # else:
                #     print('Destination Host Unreachable')
                #     eth_pkt = ethernet.ethernet(dst = eth.src, src = left_switch_router_mac, ethertype = eth.ethertype)
                #     ipv4_pkt = ipv4.ipv4(dst=src_Ip, src=left_switch_router_ip, proto=ip_pkt.proto)
                #     if ipv4_pkt.proto == inet.IPPROTO_ICMP:
                #         icmp_pkt = icmp.icmp(type_=icmp.ICMP_DEST_UNREACH, code=icmp.ICMP_HOST_UNREACH_CODE, csum=0, data=icmp.dest_unreach(data_len=len(pkt.data), data=pkt.data))
                #     match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP,nw_src=left_switch_router_ip, nw_dst=src_Ip)
                #     actions = [datapath.ofproto_parser.OFPActionSetDlSrc(left_switch_router_mac),
                #                 datapath.ofproto_parser.OFPActionSetDlDst(eth.src),
                #                 datapath.ofproto_parser.OFPActionOutput(msg.in_port, 0)]
                #     self.add_flow(datapath, match, actions)
               
                #Send Packet
                pkt.add_protocol(eth_pkt)
                pkt.add_protocol(ipv4_pkt)
                pkt.add_protocol(icmp_pkt)
                pkt.serialize()
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
                datapath.send_msg(out)
                self.logger.info("STALTHIKE EPITELOUS packet in %s %s %s %s in_port=%s", hex(dpid), hex(ethertype), src, dst, msg.in_port)
                

                if '192.168.1' not in dst_Ip and '192.168.2' not in dst_Ip:
                    eth_pkt = ethernet.ethernet(dst = eth.src, src = left_switch_router_mac, ethertype = eth.ethertype)
                    ipv4_pkt = ipv4.ipv4(dst=src_Ip, src=left_switch_router_ip, proto=ip_pkt.proto)
                    if ipv4_pkt.proto == inet.IPPROTO_ICMP:
                        icmp_pkt = icmp.icmp(type_=icmp.ICMP_DEST_UNREACH, code=icmp.ICMP_HOST_UNREACH_CODE, csum=0, data=icmp.dest_unreach(data_len=len(pkt.data), data=pkt.data))
                    pkt.add_protocol(eth_pkt)
                    pkt.add_protocol(ipv4_pkt)
                    pkt.add_protocol(icmp_pkt)
                    pkt.serialize()
                    out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
                    datapath.send_msg(out)
                return 
            return
        #Right Router
        if dpid == 0x1B:
            if ethertype == ether_types.ETH_TYPE_ARP: # this packet is ARP packet
                """
                fill in the code here
                """
                arp_pkt = pkt.get_protocol(arp.arp)

                dst_Ip = arp_pkt.dst_ip
                src_Ip = arp_pkt.src_ip
                dst_Mac = eth.dst
                src_Mac = eth.src


                if dst_Ip == left_switch_router_ip:
                    dst_Mac = eth.src
                    dst_Ip = src_Ip
                    src_Mac = left_switch_router_mac
                    src_Ip = left_switch_router_ip

                elif dst_Ip == right_switch_router_ip:
                    dst_Mac = eth.src
                    dst_Ip = src_Ip
                    src_Mac = right_switch_router_mac
                    src_Ip = right_switch_router_ip

                pkt_reply = packet.Packet()
                pkt_reply.add_protocol(ethernet.ethernet(dst=dst_Mac, 
                                                         src=src_Mac, 
                                                         ethertype=eth.ethertype))
                pkt_reply.add_protocol(arp.arp(opcode=arp.ARP_REPLY,
                                               src_mac=src_Mac,
                                               src_ip=src_Ip,
                                               dst_mac=dst_Mac,
                                               dst_ip=dst_Ip))
                pkt_reply.serialize()

                #Send packet out
                actions = [datapath.ofproto_parser.OFPActionOutput(msg.in_port, 0)]
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, 
                                                           buffer_id=ofproto.OFP_NO_BUFFER,
                                                           in_port=datapath.ofproto.OFPP_CONTROLLER, 
                                                           actions=actions, 
                                                           data=pkt_reply.data)
                datapath.send_msg(out)
                print('ARP REPLY SENT')
                #self.logger.info("MY FUCKING packet in %s %s %s %s in_port=%s", hex(dpid), hex(ethertype), src, dst, msg.in_port)
                return
            elif ethertype == ether_types.ETH_TYPE_IP: # this packet is IP packet
                """
                fill in the code here
                """
                #Get IPv4 protocol Headers Elements
                ip_pkt = pkt.get_protocol(ipv4.ipv4)                
                src_Ip = ip_pkt.src
                dst_Ip = ip_pkt.dst
                
                #Get ICMP Protocol Header Elements
                icmp_pkt = pkt.get_protocol(icmp.icmp)

                #Left Lan Packet Forwording 
                if '192.168.1' in dst_Ip:
                    if dst_Ip == h1_ip:
                        eth_pkt = ethernet.ethernet(dst=h1_mac, src=left_switch_router_mac, ethertype=eth.ethertype)
                        ipv4_pkt = ipv4.ipv4(dst=dst_Ip, src=src_Ip, proto=ip_pkt.proto)
                        icmp_pkt = icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE, csum=0, data=icmp_pkt.data)
                        out_port = 1
                        match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP,nw_src=src_Ip, nw_dst=dst_Ip)
                        actions = [datapath.ofproto_parser.OFPActionSetDlSrc(right_switch_router_mac),
                                datapath.ofproto_parser.OFPActionSetDlDst(h1_mac),
                                datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
                        self.add_flow(datapath, match, actions)
                    elif dst_Ip == h2_ip:
                        eth_pkt = ethernet.ethernet(dst=h2_mac, src=left_switch_router_mac, ethertype=eth.ethertype)
                        ipv4_pkt = ipv4.ipv4(dst=dst_Ip, src=src_Ip, proto=ip_pkt.proto)
                        icmp_pkt = icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE, csum=0, data=icmp_pkt.data)
                        out_port = 1
                        match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP,nw_src=src_Ip, nw_dst=dst_Ip)
                        actions = [datapath.ofproto_parser.OFPActionSetDlSrc(right_switch_router_mac),
                                datapath.ofproto_parser.OFPActionSetDlDst(h2_mac),
                                datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
                        self.add_flow(datapath, match, actions)
                #Right Lan Packet Forwording
                elif '192.168.2' in dst_Ip:
                    if dst_Ip == h3_ip:
                        eth_pkt = ethernet.ethernet(dst=h3_mac, src=right_switch_router_mac, ethertype=eth.ethertype)
                        ipv4_pkt = ipv4.ipv4(dst=dst_Ip, src=src_Ip, proto=ip_pkt.proto)
                        icmp_pkt = icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE, csum=0, data=icmp_pkt.data)
                        out_port = 2
                        match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP,nw_src=src_Ip, nw_dst=dst_Ip)
                        actions = [datapath.ofproto_parser.OFPActionSetDlSrc(right_switch_router_mac),
                                datapath.ofproto_parser.OFPActionSetDlDst(h3_mac),
                                datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
                        self.add_flow(datapath, match, actions)
                    elif dst_Ip == h4_ip:
                        eth_pkt = ethernet.ethernet(dst=h4_mac, src=right_switch_router_mac, ethertype=eth.ethertype)
                        ipv4_pkt = ipv4.ipv4(dst=dst_Ip, src=src_Ip, proto=ip_pkt.proto)
                        icmp_pkt = icmp.icmp(type_=icmp.ICMP_ECHO_REPLY, code=icmp.ICMP_ECHO_REPLY_CODE, csum=0, data=icmp_pkt.data)
                        out_port = 2
                        match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP,nw_src=src_Ip, nw_dst=dst_Ip)
                        actions = [datapath.ofproto_parser.OFPActionSetDlSrc(right_switch_router_mac),
                                datapath.ofproto_parser.OFPActionSetDlDst(h4_mac),
                                datapath.ofproto_parser.OFPActionOutput(out_port, 0)]
                        self.add_flow(datapath, match, actions)
                # #Unknown IP Destinations Detection
                # else:
                #     print('Destination Host Unreachable')
                #     eth_pkt = ethernet.ethernet(dst = eth.src, src = right_switch_router_mac, ethertype = eth.ethertype)
                #     ipv4_pkt = ipv4.ipv4(dst=src_Ip, src=right_switch_router_ip, proto=ip_pkt.proto)
                #     if ipv4_pkt.proto == inet.IPPROTO_ICMP:
                #         icmp_pkt = icmp.icmp(type_=icmp.ICMP_DEST_UNREACH, code=icmp.ICMP_HOST_UNREACH_CODE, csum=0, data=icmp.dest_unreach(data_len=len(pkt.data), data=pkt.data))
                #     match = datapath.ofproto_parser.OFPMatch(dl_type=ether_types.ETH_TYPE_IP,nw_src=src_Ip, nw_dst=dst_Ip)
                #     actions = [datapath.ofproto_parser.OFPActionSetDlSrc(right_switch_router_mac),
                #                 datapath.ofproto_parser.OFPActionSetDlDst(eth.src),
                #                 datapath.ofproto_parser.OFPActionOutput(msg.in_port, 0)]
                #     self.add_flow(datapath, match, actions)
                
                #Send IPv4 Packet
                pkt.add_protocol(eth_pkt)
                pkt.add_protocol(ipv4_pkt)
                pkt.add_protocol(icmp_pkt)
                pkt.serialize()
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
                datapath.send_msg(out)
                self.logger.info("STALTHIKE EPITELOUS packet in %s %s %s %s in_port=%s", hex(dpid), hex(ethertype), src, dst, msg.in_port)
                
                if '192.168.1' not in dst_Ip and '192.168.2' not in dst_Ip:
                    eth_pkt = ethernet.ethernet(dst = eth.src, src = left_switch_router_mac, ethertype = eth.ethertype)
                    ipv4_pkt = ipv4.ipv4(dst=src_Ip, src=left_switch_router_ip, proto=ip_pkt.proto)
                    if ipv4_pkt.proto == inet.IPPROTO_ICMP:
                        icmp_pkt = icmp.icmp(type_=icmp.ICMP_DEST_UNREACH, code=icmp.ICMP_HOST_UNREACH_CODE, csum=0, data=icmp.dest_unreach(data_len=len(pkt.data), data=pkt.data))
                    pkt.add_protocol(eth_pkt)
                    pkt.add_protocol(ipv4_pkt)
                    pkt.add_protocol(icmp_pkt)
                    pkt.serialize()
                    out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER, in_port=datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
                    datapath.send_msg(out)

                return
            
            return
                 
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        match = datapath.ofproto_parser.OFPMatch(
            in_port=msg.in_port, dl_dst=haddr_to_bin(dst))

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)

    """
    fill in the code here for the ARP reply functions.
    """
    # def send_arp_reply(self, datapath, parser, arp_pkt):
    #     eth_pkt = ethernet.ethernet(dst=arp_pkt.src_mac,
    #                                 src='00:00:00:00:04:01',
    #                                 ethertype=ether_types.ethertype)
    #     arp_reply = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4,
    #                         opcode=arp.ARP_REPLY, src_mac='00:00:00:00:04:01',
    #                         src_ip='192.168.1.1', dst_mac=arp_pkt.src_mac,
    #                         dst_ip=arp_pkt.src_ip)
    #     pkt_out = packet.Packet()
    #     pkt_out.add_protocol(eth_pkt)
    #     pkt_out.add_protocol(arp_reply)
    #     pkt_out.serialize()

    #     actions = [parser.OFPActionOutput(datapath.ofproto.OFPP_IN_PORT)]
    #     out = parser.OFPPacketOut(datapath=datapath,
    #                               buffer_id=datapath.ofproto.OFP_NO_BUFFER,
    #                               in_port=datapath.ofproto.OFPP_CONTROLLER,
    #                               actions=actions,
    #                               data=pkt_out.data)
    #     datapath.send_msg(out)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def _port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        port_no = msg.desc.port_no

        ofproto = msg.datapath.ofproto
        if reason == ofproto.OFPPR_ADD:
            self.logger.info("port added %s", port_no)
        elif reason == ofproto.OFPPR_DELETE:
            self.logger.info("port deleted %s", port_no)
        elif reason == ofproto.OFPPR_MODIFY:
            self.logger.info("port modified %s", port_no)
        else:
            self.logger.info("Illeagal port state %s %s", port_no, reason)