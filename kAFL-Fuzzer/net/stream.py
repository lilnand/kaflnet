import random
import struct

from logging import exception
from scapy.utils import rdpcap

from net.layers.l2 import FuzzEther

class Stream:
    def __init__(self):
        self.packets = []

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

    def init_stream_from_pcap_file(self, pcap_file):
        pcap = rdpcap(pcap_file)
 
        for p in pcap:
            _pkt = FuzzEther(bytes(p))
            self.packets.append(_pkt)

    def init_stream_from_node_payload(self, payload):
        pos = 0
        self.packets = []

        while pos < len(payload):
            hdr = payload[pos:][:16]
            sec, usec, caplen, wirelen = struct.unpack("IIII", hdr)
            pos += 16
            _pkt = FuzzEther(payload[pos:][:caplen])
            self.packets.append(_pkt)
            pos += caplen
            
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