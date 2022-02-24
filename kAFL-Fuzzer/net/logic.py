import os
import random

from scapy.packet import Packet, fuzz
from scapy.layers.inet6 import icmp6typescls, icmp6ndoptscls
from common.util import get_random_string
from net.stream import Stream

class ICMPv6Logic:
    def __init__(self, slave, config):
        self.slave = slave
        self.config = config
    
    def _write_stream_to_imports(self, stream, new_payload):
        write_path = os.path.join(self.config.argument_values['work_dir'], 'imports')
         
        if stream.size():
            #TODO create new directory in imports dir and update write_path
            pass
        
        base_seed_name = get_random_string(6)
        write_path = os.path.join(write_path, base_seed_name)
        const_payloads = stream.get_const_payloads()

        for i, cp in enumerate(const_payloads):
            current_wr_path = write_path + str(i)
            
            with open(current_wr_path, 'wb') as f:
                f.write(cp)

        with open(write_path + '1337', 'wb') as f:
            f.write(new_payload)

    def _handle_type_options(self, stream):
        payload = stream.get_payload()
        _type = payload[0]

        if _type in [133, 134, 135, 136, 137]:
            _cls = icmp6typescls[_type]
            _cls_obj = _cls(payload)
            _opt_cls = random.choice(list(icmp6ndoptscls.values()))
            _opt_cls_obj = fuzz(_opt_cls())
            
            new_payload = bytes(_cls_obj / _opt_cls_obj)
        else:
            new_payload = payload + get_random_string(random.randint(10, 1000)).encode()

        self._write_stream_to_imports(stream, new_payload)

    def process_stream(self, stream):
        self._handle_type_options(stream)