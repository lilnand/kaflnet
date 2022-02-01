from logging import exception
import random
import struct
from scapy.utils import rdpcap

class Stream:
    def __init__(self):
        self.pcap = None
        self.packets = []

    def init_stream_from_pcap_file(self, pcap_file):
        self.pcap = rdpcap(pcap_file)
 
        for p in self.pcap:
            self.packets.append(bytes(p))

    def init_stream_from_node_payload(self, payload):
        pos = 0
        self.packets = []

        while pos < len(payload):
            hdr = payload[pos:][:16]
            sec, usec, caplen, wirelen = struct.unpack("IIII", hdr)
            pos += 16
            self.packets.append(payload[pos:][:caplen])
            pos += caplen
            
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

    def raw_size(self):
        raw_size = 0
        for p in self.packets:
            raw_size += len(p)
        return raw_size

    def mutate_stream(self, handler):
        index = random.choice(range(len(self.packets)))
        self.packets[index] = handler(self.packets[index])

    def build(self):
        payload = b''
        
        for p in self.packets:
            sec = 0
            usec = 0

            caplen = len(p)
            wirelen = caplen
            payload += struct.pack("IIII", sec, usec, caplen, wirelen) + p
        
        return payload