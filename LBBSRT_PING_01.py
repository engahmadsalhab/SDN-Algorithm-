from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.revent import EventHalt
from pox.lib.packet.arp import arp
from pox.lib.packet.ethernet import ethernet

from time import sleep
from numpy import array, amin
from threading import Thread
from statistics import stdev
import random
import sys, errno
#import ping3

log = core.getLogger("LBBSRT LB - AS")

############## Globals #############

virtual_ip = IPAddr("10.0.2.1")  # virtual ip address for server
virtual_mac = EthAddr("00:00:00:00:0d:00")  # virtual mac address for server

# servers that we use them with their mac addresses
servers = {
    "10.0.0.1": "00:00:00:00:00:01",
    "10.0.0.2": "00:00:00:00:00:02",
    "10.0.0.3": "00:00:00:00:00:03"
}

ip_decision = "10.0.0.1"  # The Win server to redirect the traffic to..

samples = 20  # N number of t history values
treshold = 0.0001  # lambda

################ Handlers ###################



import socket
import struct
import time

def checksum(source_string):
    # I'm not too confident that this is right but testing seems to
    # suggest that it gives the same answers as in_cksum in ping.c.
    sum = 0
    count_to = (len(source_string) / 2) * 2
    count = 0
    while count < count_to:
        this_val = int.from_bytes(source_string[count + 1:count + 2], byteorder='big')*256+int.from_bytes(source_string[count:count + 1], byteorder='big')
        sum = sum + this_val
        sum = sum & 0xffffffff # Necessary?
        count = count + 2
    if count_to < len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff # Necessary?
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

def ping_server_once(ip_address):
    # Adapted from https://gist.github.com/pklaus/856268
    
    icmp_type = 8  # ICMP echo request
    icmp_code = 0
    icmp_checksum = 0
    icmp_id = 1
    icmp_seq = 1
    
    # Create socket and set timeout to 2 seconds
    icmp_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    icmp_socket.settimeout(2)
    
    # Build ICMP packet
    icmp_packet = struct.pack("BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    icmp_checksum = checksum(icmp_packet)
    icmp_packet = struct.pack("BBHHH", icmp_type, icmp_code, icmp_checksum, icmp_id, icmp_seq)
    
    try:
        start_time = time.time()
        icmp_socket.sendto(icmp_packet, (ip_address, 1))
        
        # Receive reply packet
        reply_packet, address = icmp_socket.recvfrom(1024)
        end_time = time.time()
        rtt_ms = int((end_time - start_time) * 1000)
        
        return rtt_ms
    
    except socket.timeout:
        return None
    
    finally:
        icmp_socket.close()




def ping_func():
    global treshold
    global samples
    global ip_decision

    # same as the used servers without mac addresses
    server_list = ['10.0.0.1', '10.0.0.2', '10.0.0.3']

    # empty list to measure the server response time and save it
    ping_itmes = list()
    for server in server_list:
        #log.info("add server (%s) to server list", server)
        ping_itmes.append(ping_to_server(server, samples))

    while True:
        current = list()
        stdev_data = list()
        for server in ping_itmes:
            ping = server.pingOnce()
            if ping is None:
                break
            current.append(ping)
            stdev_data.append(server.stdev())
        if len(current) < len(ping_itmes):
            continue
            log.info("continue in len")

        diff = abs(max(current) - min(current))
        if diff < treshold:
            winner = stdev_data.index(min(stdev_data))
            log.info("STD Win")
        else:
            winner = current.index(min(current))
            log.info("Least Loaded Server win")

        ip_decision = server_list[winner]
        #log.info("The winner server is %s", ip_decision)
        sleep(2)

class ping_to_server(object):

    def __init__(self, target, samples):  # constractor
        self.target = target  # server ip
        self.samples = samples  # number of samples
        self.data = list()  # number of the t values in the history of the server ping

    def pingOnce(self):  # save ping time to
        t = ping_server_once(self.target)
        log.info("Ping to (%s )   and Result is (%s)",self.target, t)
        if t is None:
            return None
        self.add(t)  # add the t value to the history of t values of the server
        return t

    def add(self, time):
        # insert the ping time at first of list
        self.data.insert(0, time)
        # if data list length passed samples value, remove the last value
        if len(self.data) > self.samples:
            self.data.pop()

    def stdev(self):
        if len(self.data) < 2: return 0
        return stdev(self.data)


class Switch(object):

    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

    def _handle_PacketIn(self, event):
        try:
            global ip_decision
            packet = event.parsed
            
            # ARP handling
            if packet.type == 0x0806:
                if packet.payload.opcode == arp.REQUEST and packet.payload.protodst == virtual_ip:
                        log.info("Received ARP request for %s", virtual_ip)
                        # Form a reply packet
                        arp_reply = arp()
                        arp_reply.hwsrc = virtual_mac
                        arp_reply.hwdst = packet.src
                        arp_reply.opcode = arp.REPLY
                        arp_reply.protosrc = virtual_ip
                        arp_reply.protodst = packet.payload.protosrc
                        ether = ethernet()
                        ether.type = ethernet.ARP_TYPE
                        ether.dst = packet.src
                        ether.src = virtual_mac
                        ether.payload = arp_reply

                        # send this packet to the switch
                        packet_out = of.ofp_packet_out()
                        packet_out.data = ether.pack()
                        packet_out.actions.append(of.ofp_action_output(port=of.OFPP_TABLE))
                        event.connection.send(packet_out)
                
                # Handle ICMP traffic for each server
                if packet.type == ethernet.IP_TYPE and packet.payload.protocol == pkt.ICMP_PROTOCOL:
                    for server_ip, server_mac in servers.items():
                        if packet.payload.dstip == server_ip:
                            log.info("Packet matched for server %s", server_ip)
                            msg = of.ofp_flow_mod()
                            msg.match = of.ofp_match.from_packet(packet, in_port=event.port)
                            msg.idle_timeout = of.OFP_FLOW_PERMANENT
                            msg.hard_timeout = of.OFP_FLOW_PERMANENT
                            msg.actions.append(of.ofp_action_dl_addr.set_src(virtual_mac))
                            msg.actions.append(of.ofp_action_dl_addr.set_dst(server_mac))
                            msg.actions.append(of.ofp_action_nw_addr.set_src(virtual_ip))
                            msg.actions.append(of.ofp_action_nw_addr.set_dst(server_ip))
                            msg.actions.append(of.ofp_action_output(port=of.OFPP_IN_PORT))
                            self.connection.send(msg)
                            
            # Handle traffic destined to virtual IP
            if packet.type == 0x0800:
                if packet.payload.dstip == virtual_ip:

                    # SNMP selection of servers
                    selected_server_ip = IPAddr(ip_decision)
                    selected_server_mac = EthAddr(servers[ip_decision])
                    # log.warning("server ip: %s | mac: %s", selected_server_ip,selected_server_mac)

                    #log.info("Instruction: send packet from client to server")
                    msg = of.ofp_flow_mod()
                    msg.priority = 1500
                    msg.match = of.ofp_match()
                    msg.match.dl_type = 0x0800
                    msg.match.nw_proto = 6
                    msg.match.nw_dst = virtual_ip
                    msg.match.nw_src = packet.payload.srcip
                    msg.match.tp_src = packet.payload.payload.srcport
                    msg.actions.append(
                        of.ofp_action_dl_addr(of.OFPAT_SET_DL_DST,
                                              selected_server_mac))
                    msg.actions.append(
                        of.ofp_action_nw_addr(of.OFPAT_SET_NW_DST,
                                              selected_server_ip))
                    msg.actions.append(
                        of.ofp_action_output(port=of.OFPP_NORMAL))
                    event.connection.send(msg)

                    #log.info("Instruction: send packet from server to client")
                    rev_msg = of.ofp_flow_mod()
                    rev_msg.priority = 1500
                    rev_msg.match = of.ofp_match()
                    rev_msg.match.dl_type = 0x0800
                    rev_msg.match.nw_proto = 6
                    rev_msg.match.nw_src = selected_server_ip
                    rev_msg.match.nw_dst = msg.match.nw_src
                    rev_msg.match.tp_dst = msg.match.tp_src
                    rev_msg.actions.append(
                        of.ofp_action_dl_addr(of.OFPAT_SET_DL_SRC,
                                              virtual_mac))
                    rev_msg.actions.append(
                        of.ofp_action_nw_addr(of.OFPAT_SET_NW_SRC, virtual_ip))
                    rev_msg.actions.append(
                        of.ofp_action_output(port=of.OFPP_NORMAL))
                    event.connection.send(rev_msg)
        except IOError as e:
            if e.errno == errno.EPIPE:
                pass

        return EventHalt


class proactive_flow(object):

    def __init__(self):
        self.log = log.getChild("Unknown")
        core.listen_to_dependencies(self,
                                    listen_args={'openflow': {
                                        'priority': 0
                                    }})

    def _handle_openflow_ConnectionUp(self, event):
        if event.connection is None:
            self.log.debug("Can't send table: disconnected")
            return

        # start thread
        t = Thread(target=ping_func)
        t.daemon = True
        t.start()

        # clear previous flows entries if any
        clear = of.ofp_flow_mod(command=of.OFPFC_DELETE)
        event.connection.send(clear)
        event.connection.send(of.ofp_barrier_request())

        # ARP -> PacketIn, Normal, Controller
        arp_rule = of.ofp_flow_mod()
        arp_rule.match = of.ofp_match()
        arp_rule.match.dl_type = 0x0806
        arp_rule.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        arp_rule.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        event.connection.send(arp_rule)

        # DstIP: vIP -> PacketIn, PRI: 1000
        vip_rule = of.ofp_flow_mod()
        vip_rule.match = of.ofp_match()
        vip_rule.match.dl_type = 0x0800
        vip_rule.match.nw_dst = virtual_ip
        vip_rule.priority = 1000
        vip_rule.actions.append(of.ofp_action_output(port=of.OFPP_CONTROLLER))
        event.connection.send(vip_rule)

        # Any -> Normal, PRI: 1001
        any_rule = of.ofp_flow_mod()
        any_rule.priority = 500
        any_rule.actions.append(of.ofp_action_output(port=of.OFPP_NORMAL))
        event.connection.send(any_rule)

        # initialize Switch() instance
        Switch(event.connection)


def launch():
    core.registerNew(proactive_flow)
