import random
import struct

from logging import exception
from scapy.layers.l2 import Ether
from scapy.layers.inet6 import IPv6, _ICMPv6
from scapy.packet import Packet
from scapy.utils import rdpcap

class StreamStateLogic:
    def __init__(self, slave, logic, config):
        self.slave = slave
        self.logic = logic
        self.config = config
    
    def handle_stream_initial(self, stream, metadata):
        pass
    
    def handle_stream_push(self, stream, metadata):
        pass

    def handle_stream_pop(self, stream, metadata):
        pass

    def handle_stream_shuffle(self, stream, metadata):
        pass

    def process_node(self, stream, metadata):
        self.init_stage_info()

        rand_states = ["stream/push", "stream/pop"]

        if metadata["state"]["name"] == "stream/initial":
            new_paylaod = self.handle_stream_initial(stream, metadata)
            return self.logic.create_update({"name": random.choice(rand_states)}, None), new_paylaod
        elif metadata["state"]["name"] == "stream/push":
            new_paylaod = self.handle_stream_push(stream, metadata)
            return self.logic.create_update({"name": "stream/shuffle"}, None), new_paylaod
        elif metadata["state"]["name"] == "stream/pop":
            new_paylaod = self.handle_stream_pop(stream, metadata)
            return self.logic.create_update({"name": "stream/shuffle"}, None), new_paylaod
        elif metadata["state"]["name"] == "stream/shuffle":
            new_paylaod = self.handle_stream_shuffle(stream, metadata)
            return self.logic.create_update({"name": "initial"}, None), new_paylaod
        
        return None, None

    def init_stage_info(self):
        self.stream_initial_time = 0
        self.stream_push_layer_time = 0
        self.stream_pop_layer_time = 0
        self.stream_shuffle_time = 0

class Stream:
    DEFAULT_SRC_MAC = '00:50:56:C0:00:08'
    IPV6_ETHER_TYPE = 0x86dd

    def __init__(self, config, pcap_file=None, node_payload=None):
        self.dstmac = config.argument_values['dstmac']
        self.dstip = config.argument_values['dstip']
        
        self.ethernet = Ether(src=self.DEFAULT_SRC_MAC, type=self.IPV6_ETHER_TYPE)
        self.ip = IPv6()

        if self.dstmac:
            self.ethernet['dst'] = self.dstmac
        
        if self.dstip:
            self.ip['dst'] = self.dstip

        self.packets = []

        if pcap_file:
            self._init_from_pcap_file(pcap_file)
        elif node_payload:
            self._init_from_node_payload(node_payload)

    def _modify_ethernet(self, packet):
        packet['Ether']['dst'] = self.ethernet['dst']
        packet['Ether']['src'] = self.ethernet['src']
        packet['Ether']['type'] = self.ethernet['type']

    def _modify_ipv6(self, packet):
        packet['IPv6']['dst'] = self.ip['dst']

    def _modify_packet(self, packet):
        self._modify_ethernet(packet)
        self._modify_ipv6(packet)

    def _init_from_pcap_file(self, pcap_file):
        pcap = rdpcap(pcap_file)

        for p in pcap:
            current_packet = Ether(bytes(p))
            if not self._is_icmp_layer_exist(current_packet):
                continue
            self._modify_packet(current_packet)
            self.packets.append(current_packet)
        
        if len(self.packets) == 0:
            raise exception("{} doesn't contain any packet with icmp layer")

    def _init_from_node_payload(self, payload):
        pos = 0
        self.packets = []

        while pos < len(payload):
            hdr = payload[pos:][:16]
            sec, usec, caplen, wirelen = struct.unpack("IIII", hdr)
            pos += 16
            current_packet = Ether(payload[pos:][:caplen])

            if self._is_icmp_layer_exist(current_packet):
                self._modify_packet(current_packet)
                self.packets.append(current_packet)

            pos += caplen

        if len(self.packets) == 0:
            raise exception("{} doesn't contain any packet with icmp layer")
    
    def _is_icmp_layer_exist(self, packet):
        if not isinstance(packet, Packet):
            return False

        for layer in packet.layers():
            if issubclass(layer, _ICMPv6):
                return True

        return False

    def mutate_stream(self, handler):
        index = random.choice(range(len(self.packets)))
        self.packets[index] = handler(bytes(self.packets[index]))

    def build(self):
        payload = b''
        
        for p in self.packets:
            sec = 0
            usec = 0

            caplen = len(p)
            wirelen = caplen
            payload += struct.pack("IIII", sec, usec, caplen, wirelen) + bytes(p)
        
        return payload
    
    def __getitem__(self, index):
        if index >= len(self.packets):
            raise exception('__getitem__ overflow')
        return self.packet[index]

    def __setitem__(self, key, value):
        self.packets[key] = value

    def __bytes__(self):
        return self.build()

    def __len__(self):
        return len(self.build())