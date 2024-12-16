from trex_stl_lib.api import *
import argparse
# from scapy import Ether, IP, IPv6, UDP, TCP, ARP, BOOTP, DHCP, ICMP, Padding
from scapy import *
from scapy.contrib.igmp import *

ip4_pps = 20
ip6_pps = 20
other_pps = 1

big_packet_padding = 1500
small_packet_padding = 66

# node 2&4
src_mac = "6c:b3:11:21:b6:60" # node4 ens2f0
dst_mac = "6c:b3:11:21:b6:58" # node2 ens2f0
trex_rx_mac = '6c:b3:11:21:b6:62' # node4 ens2f1
# node 3&5
src_mac = "04:3f:72:f4:40:4b" # node5 ens2f1np1
dst_mac = "04:3f:72:f4:41:16" # node3 ens5f0np0
trex_rx_mac = '04:3f:72:f4:40:4a' # node5 ens2f0np0

# Add padding to packet
def add_padding(packet: Packet, size: int) -> Packet:
    padding = max(0, size - len(packet) - 4) * 'x' # HW will add 4 bytes ethernet FCS
    return packet/padding

# Change identifier at the IP header tos field
def change_ip4_tos(packet: Packet, identifier: int) -> Packet:
    packet[IP].tos = identifier << 2
    return packet

# Change identifier at the IP header traffic class field
def change_ip6_tc(packet: Packet, identifier: int) -> Packet:
    packet[IPv6].tc = identifier << 2
    return packet

class STLS1(object):
    def __init__(self):
        # 自定义参数，可以在trex的start命令中使用-t参数传递
        self.fsize = 1500
        self.lfsize = 1500

    def create_stream(self, dir, port_id):
        src_ip4 = "192.168.3.2"
        dst_ip4 = "192.168.3.1"
        nat_dst_ip4 = "10.168.3.1"

        src_ip6 = "::3:2"
        dst_ip6 = "::3:1"

        # 使用scapy API构建报文
        pkt4_udp = (
            Ether() / IP(src=src_ip4, dst=dst_ip4) / UDP(dport=4444, sport=4444)
        )
        pkt6_udp = (
            Ether() / IPv6(src=src_ip6, dst=dst_ip6) / UDP(dport=6666, sport=6666)
        )
        pkt4_tcp = (
            Ether()
            / IP(src=src_ip4, dst=dst_ip4)
            / TCP(dport=4444, sport=4444, flags="S")
        )
        pkt6_tcp = (
            Ether()
            / IPv6(src=src_ip6, dst=dst_ip6)
            / TCP(dport=6666, sport=6666, flags="S")
        )

        # ARP request
        arp_pkt = Ether(src=trex_rx_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1,
            hwsrc=trex_rx_mac,
            hwdst="00:00:00:00:00:00",
            psrc="192.168.2.2",
            pdst="192.168.2.1",
        )

        # DHCP discover
        dhcp_pkt = (
            Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
            # / IP(proto=17, src="0.0.0.0", dst="255.255.255.255")
            / IP(proto=17, src=src_ip4, dst=dst_ip4)
            / UDP(sport=68, dport=67)
            / BOOTP(op=1, chaddr=src_mac, xid=0x10000000, htype=1, hlen=6)
            / DHCP(options=[("message-type", "discover"), ("end")])
        )

        # L2 broadcast
        broadcast_pkt = (
            Ether(src=src_mac, dst="ff:ff:ff:ff:ff:ff")
            / IP(src="192.168.3.2", dst="192.168.3.255")
            / UDP(dport=5555, sport=5555)
        )

        # Host packet ip dst is 192.168.4.2
        host_pkt = (
            Ether()
            / IP(src="192.168.3.2", dst="192.168.4.2")
            / UDP(dport=5555, sport=5555)
        )

        # ICMP echo request
        icmp_pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src="192.168.3.1", dst="192.168.1.1")
            / ICMP(type=8)
        )

        # IGMPv2 add group report
        igmpv2_pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(src="10.4.0.3", dst="224.3.0.1")
            / IGMP(type=22, gaddr="224.3.0.1")
        )

        # --报文生成中的自变量设置--
        # 无变量
        no_vm = STLScVmRaw()

        # ipv4 src IP 变量
        vm4 = STLScVmRaw(
            [
                STLVmFlowVar(
                    name="ip4_src",
                    min_value="192.168.3.2",
                    max_value="192.168.3.255",
                    size=4,
                    step=1,
                    op="inc",
                ),
                STLVmWrFlowVar(
                    fv_name="ip4_src", pkt_offset="IP.src"
                ),  # write ip to packet IP.src
                STLVmFixIpv4(offset="IP"),  # fix checksum
            ],
            cache_size=255,  # the cache size
        )

        # ipv4 nat dst IP 变量
        vm4_nat = STLScVmRaw(
            [
                STLVmFlowVar(
                    name="ip4_dst",
                    min_value="10.168.3.1",
                    max_value="10.168.3.255",
                    size=4,
                    step=1,
                    op="inc",
                ),
                STLVmWrFlowVar(
                    fv_name="ip4_dst", pkt_offset="IP.dst"
                ),  # write ip to packet IP.src
                STLVmFixIpv4(offset="IP"),  # fix checksum
            ],
            cache_size=255,  # the cache size
        )

        # ipv6 src IP 变量
        vm6 = STLScVmRaw(
            [
                STLVmFlowVar(
                    name="ip6_src",
                    min_value="0.0.0.1",
                    max_value="0.0.0.255",
                    size=4,
                    step=1,
                    op="inc",
                ),
                STLVmWrFlowVar(
                    fv_name="ip6_src", pkt_offset="IPv6.src"
                ),  # write ip to packet IP.src
                # STLVmFixChecksumHw(l3_offset='IPv6', l4_offset = 'UDP', l4_type=CTRexVmInsFixHwCs.L4_TYPE_UDP),  # fix checksum
            ],
            cache_size=255,  # the cache size
        )


        # STLPktBuilder 构建Trex报文，传入scapy构造的报文和变量设置
        # 构造网络流，这里可以控制报文的pps(会被start的 -m 参数覆盖)，延迟流的pg_id(分组id)
        stream = [
            # IPv4 UDP NAT
            STLStream(
                packet=STLPktBuilder(pkt=add_padding(change_ip4_tos(pkt4_udp, 1), big_packet_padding), vm=vm4_nat),
                mode=STLTXCont(pps=ip4_pps),
                flow_stats=STLFlowStats(pg_id=1),
            ),
            # IPv4 TCP NAT
            STLStream(
                packet=STLPktBuilder(pkt=add_padding(change_ip4_tos(pkt4_tcp, 2), big_packet_padding), vm=vm4_nat),
                mode=STLTXCont(pps=ip4_pps),
                flow_stats=STLFlowStats(pg_id=2),
            ),
            # IPv6 UDP
            STLStream(
                packet=STLPktBuilder(pkt=add_padding(change_ip6_tc(pkt6_udp, 3), big_packet_padding), vm=vm6),
                mode=STLTXCont(pps=ip6_pps),
                flow_stats=STLFlowStats(pg_id=3),
            ),
            # IPv6 TCP
            STLStream(
                packet=STLPktBuilder(pkt=add_padding(change_ip6_tc(pkt6_tcp, 4), big_packet_padding), vm=vm6),
                mode=STLTXCont(pps=ip6_pps),
                flow_stats=STLFlowStats(pg_id=4),
            ),

            # ARP（没有IP层报文，不可以加flow_stats属性）
            STLStream(
                packet=STLPktBuilder(pkt=add_padding(arp_pkt, small_packet_padding), vm=no_vm),
                mode=STLTXCont(pps=other_pps),
            ),
            # ICMP
            STLStream(
                packet=STLPktBuilder(pkt=add_padding(change_ip4_tos(icmp_pkt, 6), small_packet_padding), vm=no_vm),
                mode=STLTXCont(pps=other_pps),
                flow_stats=STLFlowStats(pg_id=6),
            ),
            # IGMPv2
            STLStream(
                packet=STLPktBuilder(pkt=add_padding(change_ip4_tos(igmpv2_pkt, 7), small_packet_padding), vm=no_vm),
                mode=STLTXCont(pps=other_pps),
                flow_stats=STLFlowStats(pg_id=7),
            ),
            # 主机报文
            STLStream(
                packet=STLPktBuilder(pkt=add_padding(change_ip4_tos(host_pkt, 8), small_packet_padding), vm=no_vm),
                mode=STLTXCont(pps=other_pps),
                flow_stats=STLFlowStats(pg_id=8),
            ),
        ]
        return stream

    def get_streams(self, direction, tunables, **kwargs):
        parser = argparse.ArgumentParser(
            description="Argparser for {}".format(os.path.basename(__file__)),
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        )
        # 自定义的参数解析和设置
        parser.add_argument(
            "--fsize",
            type=int,
            default=1500,
            help="The packets size in the regular stream",
        )
        parser.add_argument(
            "--lfsize",
            type=int,
            default=1500,
            help="The packets size in the latency stream",
        )
        args = parser.parse_args(tunables)
        self.fsize = args.fsize
        self.lfsize = args.lfsize
        return self.create_stream(direction, kwargs["port_id"])


# dynamic load - used for trex console or simulator
def register():
    return STLS1()
