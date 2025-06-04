# 华为8条流，pareto分布流量模板
from trex_stl_lib.api import *
import argparse
# from scapy import Ether, IP, IPv6, UDP, TCP, ARP, BOOTP, DHCP, ICMP, Padding
from scapy import *
from scapy.contrib.igmp import *
from pareto_dict_5a import pareto_dict
import ipaddress

# 不同node的发包/收包网卡MAC地址
# node 2&4
node4_src_mac = "6c:b3:11:21:b6:60" # node4 ens2f0
node2_dst_mac = "6c:b3:11:21:b6:58" # node2 ens2f0
node4_trex_rx_mac = '6c:b3:11:21:b6:62' # node4 ens2f1
# node 3&5
node3_src_mac = "04:3f:72:f4:40:4b" # node5 ens2f1np1
node5_dst_mac = "04:3f:72:f4:41:16" # node3 ens5f0np0
node3_trex_rx_mac = '04:3f:72:f4:40:4a' # node5 ens2f0np0

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

def change_ip6_protocol_num(packet: Packet, identifier: int) -> Packet:
    # 将源地址转换为字节数组
    src_string: str = packet[IPv6].src
    # print(f"src_string before: {src_string}")
    ipv6_obj = ipaddress.IPv6Address(src_string)
    ipv6_bytes = list(ipv6_obj.packed)
    # 修改第4个字节的值，来区分protocol
    ipv6_bytes[3] = identifier
    modified_ipv6_str = str(ipaddress.IPv6Address(bytes(ipv6_bytes)))
    # print(f"src_string after: {modified_ipv6_str}")
    # 将修改后的字节数组转换回字符串
    packet[IPv6].src = modified_ipv6_str
    return packet


class STLS1(object):
    def __init__(self):
        # 流量模板默认配置，可以在trex的start命令中使用-t参数传递来覆盖
        # 包大小
        self.big_packet_padding = 1500
        self.small_packet_padding = 66
        # 使用 node3/4 trex 发包网卡的 MAC 地址，默认配置使用 node3，在node2,4上跑实验需要修改
        self.src_mac = node4_src_mac
        self.dst_mac = node2_dst_mac
        self.trex_rx_mac = node4_trex_rx_mac
        # pareto分布的a参数
        self.pareto_alpha = 1
        self.workload_num = 8

    def create_stream(self, dir, port_id):
        src_ip4 = "192.168.3.2"
        dst_ip4 = "192.168.3.1"
        nat_dst_ip4 = "10.168.3.1"

        # 固定的IPv6源地址的第一个字节为ff，使其经过dispatcher节点时被识别为IPv6流量
        src_ip6 = "ff00::3:2"
        src_ip6_protocol = "::3:2"
        dst_ip6 = "::3:1"

        # 使用scapy API构建报文
        pkt4_udp = (
            Ether() / IP(src=src_ip4, dst=dst_ip4) / UDP(dport=4444, sport=4444)
        )
        pkt6_udp = (
            Ether() / IPv6(src=src_ip6, dst=dst_ip6) / UDP(dport=6666, sport=6666)
        )
        pkt6_udp_protocol = (
            Ether() / IPv6(src=src_ip6_protocol, dst=dst_ip6) / UDP(dport=6666, sport=6666)
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
        arp_pkt = Ether(src=self.trex_rx_mac, dst="ff:ff:ff:ff:ff:ff") / ARP(
            op=1,
            hwsrc=self.trex_rx_mac,
            hwdst="00:00:00:00:00:00",
            psrc="192.168.2.2",
            pdst="192.168.2.1",
        )

        # DHCP discover
        dhcp_pkt = (
            Ether(src=self.src_mac, dst="ff:ff:ff:ff:ff:ff")
            # / IP(proto=17, src="0.0.0.0", dst="255.255.255.255")
            / IP(proto=17, src=src_ip4, dst=dst_ip4)
            / UDP(sport=68, dport=67)
            / BOOTP(op=1, chaddr=self.src_mac, xid=0x10000000, htype=1, hlen=6)
            / DHCP(options=[("message-type", "discover"), ("end")])
        )

        # L2 broadcast
        broadcast_pkt = (
            Ether(src=self.src_mac, dst="ff:ff:ff:ff:ff:ff")
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
            Ether(src=self.src_mac, dst=self.dst_mac)
            / IP(src="192.168.3.1", dst="192.168.1.1")
            / ICMP(type=8)
        )

        # IGMPv2 add group report
        igmpv2_pkt = (
            Ether(src=self.src_mac, dst=self.dst_mac)
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
                    min_value=0xff000001,
                    max_value=0xff0000ff,
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
        big_flow_stream = [
            # IPv4 UDP
            STLStream(
                name="IPv4 UDP",
                packet=STLPktBuilder(pkt=add_padding(change_ip4_tos(pkt4_udp, 1), self.big_packet_padding), vm=vm4),
                mode=STLTXCont(pps=pareto_dict[self.workload_num][self.pareto_alpha][0]),
                flow_stats=STLFlowStats(pg_id=1),
            ),
            # IPv4 TCP NAT
            STLStream(
                name="IPv4 TCP NAT",
                packet=STLPktBuilder(pkt=add_padding(change_ip4_tos(pkt4_tcp, 2), self.big_packet_padding), vm=vm4_nat),
                mode=STLTXCont(pps=pareto_dict[self.workload_num][self.pareto_alpha][1]),
                flow_stats=STLFlowStats(pg_id=2),
            ),
            # IPv6 UDP
            STLStream(
                name="IPv6 UDP",
                packet=STLPktBuilder(pkt=add_padding(change_ip6_tc(pkt6_udp, 3), self.big_packet_padding), vm=vm6),
                mode=STLTXCont(pps=pareto_dict[self.workload_num][self.pareto_alpha][2]),
                flow_stats=STLFlowStats(pg_id=3),
            ),
            # IPv6 TCP
            STLStream(
                name="IPv6 TCP",
                packet=STLPktBuilder(pkt=add_padding(change_ip6_tc(pkt6_tcp, 4), self.big_packet_padding), vm=vm6),
                mode=STLTXCont(pps=pareto_dict[self.workload_num][self.pareto_alpha][3]),
                flow_stats=STLFlowStats(pg_id=4),
            ),
        ]

        small_flow_stream = [
            # ARP（没有IP层报文，不可以加flow_stats属性）
            STLStream(
                name="ARP",
                packet=STLPktBuilder(pkt=add_padding(arp_pkt, self.small_packet_padding), vm=no_vm),
                mode=STLTXCont(pps=pareto_dict[self.workload_num][self.pareto_alpha][4]),
            ),
            # ICMP
            STLStream(
                name="ICMP",
                packet=STLPktBuilder(pkt=add_padding(change_ip4_tos(icmp_pkt, 6), self.small_packet_padding), vm=no_vm),
                mode=STLTXCont(pps=pareto_dict[self.workload_num][self.pareto_alpha][5]),
                flow_stats=STLFlowStats(pg_id=6),
            ),
            # IGMPv2
            STLStream(
                name="IGMPv2",
                # IGMPv2 无法添加padding，因为IGMPv2报文长度固定，不然会导致checksum错误
                packet=STLPktBuilder(pkt=change_ip4_tos(igmpv2_pkt, 7), vm=no_vm),
                mode=STLTXCont(pps=pareto_dict[self.workload_num][self.pareto_alpha][6]),
                flow_stats=STLFlowStats(pg_id=7),
            ),
            # 主机报文
            STLStream(
                name="Host Packet",
                packet=STLPktBuilder(pkt=add_padding(change_ip4_tos(host_pkt, 8), self.small_packet_padding), vm=no_vm),
                mode=STLTXCont(pps=pareto_dict[self.workload_num][self.pareto_alpha][7]),
                flow_stats=STLFlowStats(pg_id=8),
            ),
        ]

        return big_flow_stream + small_flow_stream

    def get_streams(self, direction, tunables, **kwargs):
        parser = argparse.ArgumentParser(
            description="Dynamic Pareto Traffic Stream",
            formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        )
        # 自定义的参数解析和设置
        parser.add_argument(
            "--big_packet_padding",
            type=int,
            help="The packets size for elephant flows",
        )
        parser.add_argument(
            "--small_packet_padding",
            type=int,
            help="The packets size for mouse flows",
        )
        parser.add_argument(
            "--trex_server",
            type=str,
            choices=["node4", "node3"],
            help="The trex server, must be 'node4' or 'node3'",
        )
        parser.add_argument(
            "--workload_num",
            type=int,
            help="flow workload numbers",
        )
        parser.add_argument(
            "--pareto_alpha",
            type=float,
            help="alpha for pareto distribution, must in [0.6, 0.8, 1, 1.2, 1.4]",
        )

        args = parser.parse_args(tunables)

        # 设置流量模板参数配置
        if args.big_packet_padding is not None:
            self.big_packet_padding = args.big_packet_padding
        if args.small_packet_padding is not None:
            self.small_packet_padding = args.small_packet_padding
        # 根据传入的参数设置MAC地址
        # 如果没有传入trex_server参数，则使用默认的node3的MAC地址
        if args.trex_server is not None:
            if args.trex_server == "node4":
                self.src_mac = node4_src_mac
                self.dst_mac = node2_dst_mac
                self.trex_rx_mac = node4_trex_rx_mac
            elif args.trex_server == "node3":
                self.src_mac = node3_src_mac
                self.dst_mac = node5_dst_mac
                self.trex_rx_mac = node3_trex_rx_mac
            else:
                raise ValueError("Invalid trex server node")
        else:
            print("Using default MAC setting for node3...")

        if args.workload_num is not None:
            self.workload_num = args.workload_num
        if args.pareto_alpha is not None:
            self.pareto_alpha = args.pareto_alpha

        stream: list[STLStream] = self.create_stream(direction, kwargs["port_id"])
        print("-----------------------------------------")
        print(f"Current traffic setting:\n-> {self.__dict__}")
        print(f"Current stream: ")
        for i, s in enumerate(stream):
            print(f"{i}. {s.name}, pps={s.fields['mode']}")
        print("-----------------------------------------")
        return stream


# dynamic load - used for trex console or simulator
def register():
    return STLS1()
