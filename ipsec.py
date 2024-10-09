from scapy.all import *
import binascii

# # Create an IPSec packet
# wrapper_packet = Ether()/IP(src="192.161.0.1", dst="192.162.0.1")
# base_packet = IP(src="192.81.0.1", dst="192.82.0.1")/UDP(dport=1234,sport=2345)
# sa = SecurityAssociation(ESP, spi=100000, crypt_algo="AES-GCM", crypt_key=b'\x4a\x50\x6a\x79\x4f\x57\x42\x65\x56\x45\x51\x69\x4d\x65\x37\x68\x12\x34\x56\x78',
#                          tunnel_header=IP(proto=1, src="192.161.0.1",dst="192.162.0.1"))
# ipsec_packet = sa.encrypt(base_packet)

# # Create a list of packets
# packet_list = [ipsec_packet]

# # Write the packets to a pcap file
# wrpcap("ipsec_packet.pcap", packet_list)


size = 1500
base_packet = IP(src="192.81.0.1", dst="192.82.0.1")/UDP(dport=1234,sport=2345)
pad = max(0, size - len(base_packet)) * 'x'
base_packet = base_packet/pad

sa = SecurityAssociation(ESP, spi=100000, crypt_algo="AES-GCM", crypt_key=b'\x4a\x50\x6a\x79\x4f\x57\x42\x65\x56\x45\x51\x69\x4d\x65\x37\x68\x12\x34\x56\x78',
                    tunnel_header=IP(proto=1, src="192.161.0.1",dst="192.162.0.1"))
ipsec_packet = sa.encrypt(base_packet)
packet_list = [ipsec_packet]
wrpcap("ipsec_packet.pcap", packet_list)