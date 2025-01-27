# 华为8条流，pareto分布流量模板
from trex_stl_lib.api import *
import argparse
# from scapy import Ether, IP, IPv6, UDP, TCP, ARP, BOOTP, DHCP, ICMP, Padding
from scapy import *
from scapy.contrib.igmp import *
from pareto_dict import pareto_dict
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
        self.src_mac = node3_src_mac
        self.dst_mac = node5_dst_mac
        self.trex_rx_mac = node3_trex_rx_mac
        # pareto分布的a参数
        self.pareto_alpha = 1
        self.workload_num = 8

    def create_stream(self, dir, port_id):

        src_ip6 = "::3:2"
        dst_ip6 = "::3:1"

        pkt6_udp = (
            Ether() / IPv6(src=src_ip6, dst=dst_ip6) / UDP(dport=6666, sport=6666)
        )

        # 无变量
        no_vm = STLScVmRaw()

        # STLPktBuilder 构建Trex报文，传入scapy构造的报文和变量设置
        # 构造网络流，这里可以控制报文的pps(会被start的 -m 参数覆盖)，延迟流的pg_id(分组id)
        protocol_flow_stream = [
            STLStream(
                name=f"IPv6 UDP protocol{i}",
                packet=STLPktBuilder(pkt=add_padding(change_ip6_protocol_num(change_ip6_tc(pkt6_udp, 1), i), self.big_packet_padding), vm=no_vm),
                mode=STLTXCont(pps=pareto_dict[self.workload_num][self.pareto_alpha][i]),
                flow_stats=STLFlowStats(pg_id=1),
            )
            for i in range(self.workload_num)
        ]
        return protocol_flow_stream

    def get_streams(self, direction, tunables, **kwargs):
        parser = argparse.ArgumentParser(
            description="Argparser for {}".format(os.path.basename(__file__)),
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
        # ---------下面的参数暂时废弃，因实验脚本兼容原因暂时保留-------
        parser.add_argument(
            "--ip4_pps",
            type=int,
            help="The packets per second for IPv4 flows",
        )
        parser.add_argument(
            "--ip6_pps",
            type=int,
            help="The packets per second for IPv6 flows",
        )
        parser.add_argument(
            "--other_pps",
            type=int,
            help="The packets per second for other four small flows",
        )
        parser.add_argument(
            "--small_flow_count",
            type=int,
            help="Small flow count in traffic profile",
        )
        parser.add_argument(
            "--big_flow_count",
            type=int,
            help="Big flow count in traffic profile",
        )
        parser.add_argument(
            "--small_flow_pps",
            type=int,
            help="Uniformly control four small flows pps",
        )
        parser.add_argument(
            "--big_flow_pps",
            type=int,
            help="Uniformly control four big flows",
        )
        # ---------------------------------------------------------
        parser.add_argument(
            "--workload_num",
            type=int,
            help="flow workload numbers",
        )
        parser.add_argument(
            "--pareto_alpha",
            type=float,
            help="alpha for pareto distribution, must in [0.8, 1, 1.5]",
        )

        args = parser.parse_args(tunables)

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
