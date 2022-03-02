from operator import index
import random
import struct
import time

from copy import deepcopy
from logging import exception

from scapy.layers.l2 import Ether
from scapy.packet import Packet, fuzz
from scapy.utils import rdpcap
from scapy.layers.inet6 import *
from scapy.layers.inet6 import _ICMPv6, ICMPv6Unknown, icmp6typescls

class Stream:
    def __init__(self, config):
        self.payload = None
        self.const_stream_payloads = []

        self.eth = Ether()
        self.ip = IPv6()
        self.packet = {'Ether': self.eth, 'IPv6': self.ip}

        if config:
            self.netconf = config
            self._init_base_layers(self.netconf)

    def _init_base_layers(self, netconf):
        for layer in ['Ether', 'IPv6']:
            if layer in list(netconf.keys()):
                for field in netconf[layer]:
                    self.packet[layer].fields[field] = netconf[layer][field]

    def set_payload(self, payload):
        self.payload = payload

    def get_payload(self):
        return self.payload

    def get_const_payloads(self):
        return self.const_stream_payloads

    def push(self, payload):
        self.const_stream_payloads.append(payload)

    def pop(self):
        return self.const_stream_payloads.pop()

    def size(self):
        return len(self.const_stream_payloads)

    def is_empty(self):
        return self.payload == None

    def loads(self, pcap_payload):
        """
        load stream payload
        """
        self.const_stream_payloads.clear()
        base_len = len(bytes(self.eth / self.ip))
        pos = 0

        while pos < len(pcap_payload):
            _, _, _, packet_len = struct.unpack("IIII", pcap_payload[pos:][:16])
            pos += 16 + base_len
            seed_len = packet_len - base_len

            seed = pcap_payload[pos:][:seed_len]
            self.push(seed)
            pos += seed_len

        if len(self.const_stream_payloads):
            self.payload = self.pop()

    def _build_icmp_type_cls(self, payload, _cls):
        print(payload)
        print(_cls)
        _cls_obj = _cls(payload)

        if not _cls == Raw:
            _cls_obj.cksum = 0
            uplen = len(_cls_obj)
            ph6 = PseudoIPv6(src=self.ip.src, dst=self.ip.dst, nh=58, uplen=uplen)
            _cls_obj.cksum = checksum(raw(ph6 / _cls_obj))
        
        packet = self.eth / self.ip / _cls_obj                
        packet['IPv6'].plen = len(_cls_obj)
        
        return packet

    def build(self):
        stream_buff = b''
        cur_seeds = self.const_stream_payloads + [self.fuzzseed]

        for p in cur_seeds:
            cls_type = p[0]

            if cls_type in list(icmp6typescls.keys()):
                if len(p) < icmp6typesminhdrlen[cls_type] and len(p) != 3:
                    _cls = ICMPv6Unknown
                elif len(p) == 3:
                    _cls = Raw
                else:
                    _cls = icmp6typescls[cls_type]
            else:
                if len(p) == 3:
                    _cls = Raw
                else:
                    _cls = ICMPv6Unknown

            packet = self._build_icmp_type_cls(p, _cls)
            packet_bytes = bytes(packet) 
            wirelen = len(packet_bytes)
            stream_buff += struct.pack("IIII", 0, 0, wirelen, wirelen) + packet_bytes

        return stream_buff       

    def show(self):
        pass
        #print(self.build()[16:])
        #Ether(self.build()[16:]).show()

class StreamStateLogic:
    def __init__(self, slave, logic, config):
        self.slave = slave
        self.logic = logic
        self.config = config
    
    def handle_kafl_stage(self, stream, metadata, func):
        new_stream = deepcopy(stream)
        index = random.randint(0, stream.size() - 1)
        
        payload = None#bytes_linked_with_stream(new_stream, index)

        return func(payload, metadata)           
        

    def handle_stream_initial(self, stream, metadata):
        time_stream_initial_start = time.time()
        iterations = 2 ** random.randint(0, 6)
        new_stream = deepcopy(stream)

        self.logic.stage_update_label("strm/init")

        for _ in range(iterations):
            packet = random.choice(new_stream.packets)
            layer_name = random.choice(packet.layers()).__name__
            layer = packet[layer_name]
            fzlayer = fuzz(layer)

            for dfname in fzlayer.default_fields:
                layer.fields[dfname] = fzlayer.default_fields[dfname]

            res, is_new = self.logic.execute(new_stream, label="stream/initial")

            if is_new:
                self.stream_initial_time += time.time() - time_stream_initial_start
                return new_stream

        self.stream_initial_time += time.time() - time_stream_initial_start
        return None

    def handle_stream_push(self, stream, metadata):
        time_stream_push_start = time.time()
        self.logic.stage_update_label("strm/push")
        
        new_stream = deepcopy(stream)
    
        for _ in range(8):
            index = random.randint(0, new_stream.size() - 1)
            cls = random.choice(list(icmp6typescls.values()))
            new_stream[index].add_payload(fuzz(cls()))

            _, is_new = self.logic.execute(new_stream, label="stream/push")
            
            if is_new:
                self.stream_push_layer_time = time.time() - time_stream_push_start
                return new_stream

        self.stream_push_layer_time = time.time() - time_stream_push_start
        return new_stream

        
    def handle_stream_pop(self, stream, metadata):
        time_stream_pop_start = time.time()
        self.logic.stage_update_label("strm/pop")

        new_stream = deepcopy(stream)
        
        for _ in range(8):
            index = random.randint(0, new_stream.size()-1)
            layers_len = len(new_stream[index].layers()) - 1
            remove_payload_from = random.randint(1, layers_len)
            new_stream[index][remove_payload_from].remove_payload()

            _, is_new = self.logic.execute(new_stream, label="stream/push")
            
            if is_new:
                self.stream_pop_layer_time = time.time() - time_stream_pop_start
                return new_stream

        self.stream_pop_layer_time = time.time() - time_stream_pop_start
        return new_stream

    def handle_stream_shuffle(self, stream, metadata):
        time_stream_shuffle_start = time.time()
        self.logic.stage_update_label("strm/shuffle")

        new_stream = deepcopy(stream)

        for _ in range(8):
            index = random.randint(0, new_stream.size() - 1)
            shuffle_layers = random.shuffle(new_stream[index].layers()[2:])
            
            if shuffle_layers:
                new_stream[index][1].remove_payload()
                for l in shuffle_layers:
                    new_stream[index].add_payload(fuzz(l))
                
                _, is_new = self.logic.execute(new_stream, label="stream/shuffle")
                
                if is_new:
                    self.stream_shuffle_time = time.time() - time_stream_shuffle_start
                    return new_stream
        
        self.stream_shuffle_time = time.time() - time_stream_shuffle_start
        return new_stream

    def process_node(self, stream, metadata):
        self.init_stage_info()

        rand_states = ["stream/push", "stream/pop", "stream/shuffle"]

        if metadata["state"]["name"] == "stream/initial":
            new_stream = self.handle_stream_initial(stream, metadata)
            return self.logic.create_update({"name": random.choice(rand_states)}, None), new_stream
        elif metadata["state"]["name"] == "stream/push":
            new_paylaod = self.handle_stream_push(stream, metadata)
            return self.logic.create_update({"name": "stream/shuffle"}, None), new_paylaod
        elif metadata["state"]["name"] == "stream/pop":
            new_paylaod = self.handle_stream_pop(stream, metadata)
            return self.logic.create_update({"name": "stream/shuffle"}, None), new_paylaod
        elif metadata["state"]["name"] == "stream/shuffle":
            new_paylaod = self.handle_stream_shuffle(stream, metadata)
            return self.logic.create_update({"name": "final"}, None), new_paylaod
        elif metadata["state"]["name"] == "final":
            new_stream = self.handle_stream_initial(stream, metadata)
            return self.logic.create_update({"name": random.choice(rand_states)}, None), new_stream
        else:
            raise ValueError("Unknown task stage %s" % metadata["state"]["name"])

    def init_stage_info(self):
        self.stream_initial_time = 0
        self.stream_push_layer_time = 0
        self.stream_pop_layer_time = 0
        self.stream_shuffle_time = 0

class _Stream:
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
        packet['Ether'].fields['dst'] = self.ethernet.dst
        packet['Ether'].fields['src'] = self.ethernet.src
        packet['Ether'].fields['type'] = self.ethernet.type

    def _modify_ipv6(self, packet):
        packet['IPv6'].fields['dst'] = self.ip.dst

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

    def size(self):
        return len(self.packets)

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
        return self.packets[index]

    def __setitem__(self, index, value):
        if index >= len(self.packets):
            raise exception('__getitem__ overflow')
        self.packets[index] = value

    def __bytes__(self):
        return self.build()

    def __len__(self):
        return len(self.build())