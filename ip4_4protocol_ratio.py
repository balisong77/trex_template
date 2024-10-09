from trex_stl_lib.api import *
import argparse



# split the range of IP to cores 
# add tunable by fsize to change the size of the frame 
# latency frame is always 64 
# trex>start -f stl/udp_1pkt_src_ip_split_latency.py -t fsize=64 -m 30% --port 0 --force
#
#

class STLS1(object):

    def __init__ (self):
        # 自定义参数，可以在trex的start命令中使用-t参数传递
        self.fsize = 9000
        self.lfsize = 9000
        self.protocol1_ratio = 1
        self.protocol2_ratio = 1
        self.protocol3_ratio = 1
        self.protocol4_ratio = 1


    def create_stream (self, dir, port_id):
        # Create base packet and pad it to size
        size = self.fsize - 4; # HW will add 4 bytes ethernet FCS

        # VPP protocolx 插件里通过 u8 ip_src[4] 中的 ip_src[0] 为1~4来区分不同的协议，由于网络序为大段序，所以实际判断的是 "a.b.c.d" 中的 a
        src_ip4_protocol1="1.168.1.1"
        src_ip4_protocol2="2.168.1.1"
        src_ip4_protocol3="3.168.1.1"
        src_ip4_protocol4="4.168.1.1"
        dst_ip4="192.168.3.1"


        # 使用scapy API构建报文
        base_pkt4_protocol1 = Ether()/IP(src=src_ip4_protocol1,dst=dst_ip4)/UDP(dport=4444,sport=4444)
        base_pkt4_protocol2 = Ether()/IP(src=src_ip4_protocol2,dst=dst_ip4)/UDP(dport=4444,sport=4444)
        base_pkt4_protocol3 = Ether()/IP(src=src_ip4_protocol3,dst=dst_ip4)/UDP(dport=4444,sport=4444)
        base_pkt4_protocol4 = Ether()/IP(src=src_ip4_protocol4,dst=dst_ip4)/UDP(dport=4444,sport=4444)

        # 计算填充长度，生成报文填充
        pad = max(0, size - len(base_pkt4_protocol1)) * 'x'
        pad_latency = max(0, (self.lfsize-4) - len(base_pkt4_protocol1)) * 'x'

        # 报文生成中的自变量，这里例子是控制ip_src++，范围从
        vm4_1 = STLScVmRaw( [   STLVmFlowVar ( "ip_src",  min_value="1.168.1.1",
                                            max_value="1.168.4.255", size=4, step=1,op="inc"),
                             STLVmWrFlowVar (fv_name="ip_src", pkt_offset= "IP.src" ), # write ip to packet IP.src
                             STLVmFixIpv4(offset = "IP")                                # fix checksum
                                  ]
                              ,cache_size =255*4 # the cache size
                              )
        vm4_2 = STLScVmRaw( [   STLVmFlowVar ( "ip_src",  min_value="2.168.1.1",
                                            max_value="2.168.4.255", size=4, step=1,op="inc"),
                             STLVmWrFlowVar (fv_name="ip_src", pkt_offset= "IP.src" ), # write ip to packet IP.src
                             STLVmFixIpv4(offset = "IP")                                # fix checksum
                                  ]
                              ,cache_size =255*4 # the cache size
                              )
        vm4_3 = STLScVmRaw( [   STLVmFlowVar ( "ip_src",  min_value="3.168.1.1",
                                            max_value="3.168.4.255", size=4, step=1,op="inc"),
                             STLVmWrFlowVar (fv_name="ip_src", pkt_offset= "IP.src" ), # write ip to packet IP.src
                             STLVmFixIpv4(offset = "IP")                                # fix checksum
                                  ]
                              ,cache_size =255*4 # the cache size
                              )
        vm4_4 = STLScVmRaw( [   STLVmFlowVar ( "ip_src",  min_value="4.168.1.1",
                                            max_value="4.168.4.255", size=4, step=1,op="inc"),
                             STLVmWrFlowVar (fv_name="ip_src", pkt_offset= "IP.src" ), # write ip to packet IP.src
                             STLVmFixIpv4(offset = "IP")                                # fix checksum
                                  ]
                              ,cache_size =255*4 # the cache size
                              )

        # 构建Trex报文，传入scapy构造的报文和变量设置
        pkt4_protocol1 = STLPktBuilder(pkt = base_pkt4_protocol1/pad,
                            vm = vm4_1)
        pkt4_protocol2 = STLPktBuilder(pkt = base_pkt4_protocol2/pad,
                            vm = vm4_2)
        pkt4_protocol3 = STLPktBuilder(pkt = base_pkt4_protocol3/pad,
                            vm = vm4_3)
        pkt4_protocol4 = STLPktBuilder(pkt = base_pkt4_protocol4/pad,
                            vm = vm4_4)

        pkt4_protocol1_latency = STLPktBuilder(pkt = base_pkt4_protocol1/pad_latency,
                            vm = vm4_1)
        pkt4_protocol2_latency = STLPktBuilder(pkt = base_pkt4_protocol2/pad_latency,
                            vm = vm4_2)
        pkt4_protocol3_latency = STLPktBuilder(pkt = base_pkt4_protocol3/pad_latency,
                            vm = vm4_3)
        pkt4_protocol4_latency = STLPktBuilder(pkt = base_pkt4_protocol4/pad_latency,
                            vm = vm4_4)


        # 构造网络流，这里可以控制报文的pps(会被start的 -m 参数覆盖)，延迟流的pg_id(分组id)
        stream = [
                  # IPv4 protocol1
                  STLStream(packet = pkt4_protocol1,
                            mode = STLTXCont(pps=self.protocol1_ratio),
                            flow_stats= STLFlowStats(pg_id = port_id + 10)),
                  # IPv4 protocol1 延迟流
                  STLStream(packet = pkt4_protocol1_latency,
                            mode = STLTXCont(pps=1000),
                            flow_stats = STLFlowLatencyStats(pg_id = port_id + 110)),
                  
                  # IPv4 protocol2
                  STLStream(packet = pkt4_protocol2,
                            mode = STLTXCont(pps=self.protocol2_ratio),
                            flow_stats= STLFlowStats(pg_id = port_id + 20)),
                  # IPv4 protocol2 延迟流
                  STLStream(packet = pkt4_protocol2_latency,
                            mode = STLTXCont(pps=1000),
                            flow_stats = STLFlowLatencyStats(pg_id = port_id + 220)),
                
                  # IPv4 protocol3
                  STLStream(packet = pkt4_protocol3,
                            mode = STLTXCont(pps=self.protocol3_ratio),
                            flow_stats= STLFlowStats(pg_id = port_id + 30)),
                  # IPv4 protocol3 延迟流
                  STLStream(packet = pkt4_protocol3_latency,
                            mode = STLTXCont(pps=1000),
                            flow_stats = STLFlowLatencyStats(pg_id = port_id + 330)),
                
                #   # IPv4 protocol4
                #   STLStream(packet = pkt4_protocol4,
                #             mode = STLTXCont(pps=self.protocol4_ratio),
                #             flow_stats= STLFlowStats(pg_id = port_id + 40)),
                #   # IPv4 protocol4 延迟流
                #   STLStream(packet = pkt4_protocol4_latency,
                #             mode = STLTXCont(pps=1000),
                #             flow_stats = STLFlowLatencyStats(pg_id = port_id + 440)),
        ]
        return stream


    def get_streams (self, direction, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        # 自定义的参数解析和设置
        parser.add_argument('--fsize',
                            type=int,
                            default=9000,
                            help="The packets size in the regular stream")
        parser.add_argument('--lfsize',
                            type=int,
                            default=9000,
                            help="The packets size in the latency stream")
        parser.add_argument('--ip4_ratio',
                    type=int,
                    default=1,
                    help="ip4_ratio")
        parser.add_argument('--ip6_ratio',
            type=int,
            default=1,
            help="ip6_ratio")
        args = parser.parse_args(tunables)

        self.fsize = args.fsize
        self.lfsize = args.lfsize
        # 获取自动化脚本传入的比例参数
        self.ip4_ratio = args.ip4_ratio
        self.ip6_ratio = args.ip6_ratio

        return self.create_stream(direction,kwargs['port_id'])


# dynamic load - used for trex console or simulator
def register():
    return STLS1()



