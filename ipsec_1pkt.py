from trex_stl_lib.api import *
import argparse


class STLS1(object):

    def __init__ (self):
        self.mode  =0;
        self.fsize  =200;

    def create_stream (self):
        # Create base packet and pad it to size
        size = self.fsize - 4; # HW will add 4 bytes ethernet FCS

        base_packet = IP(src="192.81.0.3", dst="192.82.0.2")/UDP(dport=1234,sport=2345)
        pad = max(0, size - len(base_packet)) * 'x'
        base_packet = base_packet/pad

        sa = SecurityAssociation(ESP, spi=100000, crypt_algo="AES-GCM", crypt_key=b'\x4a\x50\x6a\x79\x4f\x57\x42\x65\x56\x45\x51\x69\x4d\x65\x37\x68\x12\x34\x56\x78',
                                 tunnel_header=IP(proto=1, src="192.161.0.1",dst="192.162.0.1",
                                 seq_num=1))
        ipsec_packet = sa.encrypt(base_packet)
        ipsec_packet = Ether()/ipsec_packet

        pkt = STLPktBuilder(pkt = ipsec_packet,
                            vm = [])

        return STLStream(packet = pkt,
                         mode = STLTXCont())



    def get_streams (self, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)

        args = parser.parse_args(tunables)
        # create 1 stream 
        return [ self.create_stream() ]


# dynamic load - used for trex console or simulator
def register():
    return STLS1()



