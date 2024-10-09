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
        self.fsize = 1500
        self.lfsize = 1500


    def create_stream (self, dir, port_id):
        # Create base packet and pad it to size
        size = self.fsize - 4 # HW will add 4 bytes ethernet FCS

        src_ip4="1.168.1.1"
        dst_ip4="192.168.3.1"

        # 使用scapy API构建报文
        base_pkt4 = Ether()/IP(src=src_ip4,dst=dst_ip4)/UDP(dport=4444,sport=4444)

        # 计算填充长度，生成报文填充
        pad = max(0, size - len(base_pkt4)) * 'x'
        pad_latency = max(0, (self.lfsize-4) - len(base_pkt4)) * 'x'

        # 报文生成中的自变量，这里例子是控制ip_src++，范围从
        vm4 = STLScVmRaw( [   STLVmFlowVar ( "ip_src",  min_value="1.168.1.1",
                                            max_value="1.168.4.255", size=4, step=1,op="inc"),
                             STLVmWrFlowVar (fv_name="ip_src", pkt_offset= "IP.src" ), # write ip to packet IP.src
                             STLVmFixIpv4(offset = "IP")                                # fix checksum
                                  ]
                              ,cache_size = 255*4 # the cache size
                              )

        # 构建Trex报文，传入scapy构造的报文和变量设置
        pkt4 = STLPktBuilder(pkt = base_pkt4/pad,
                            vm = vm4)

        # 构造网络流，这里可以控制报文的pps(会被start的 -m 参数覆盖)，延迟流的pg_id(分组id)
        stream = [
                  # IPv4
                  STLStream(packet = pkt4,
                            mode = STLTXCont(pps=1),
                            flow_stats= STLFlowStats(pg_id = port_id + 10)),
                  # IPv4 延迟流
                #   STLStream(packet = STLPktBuilder(pkt = base_pkt4/pad_latency),
                #             mode = STLTXCont(pps=1000),
                #             flow_stats = STLFlowLatencyStats(pg_id = (port_id+1) * 10 + 4)),
        ]
        return stream


    def get_streams (self, direction, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        # 自定义的参数解析和设置
        parser.add_argument('--fsize',
                            type=int,
                            default=1500,
                            help="The packets size in the regular stream")
        parser.add_argument('--lfsize',
                            type=int,
                            default=1500,
                            help="The packets size in the latency stream")
        args = parser.parse_args(tunables)
        self.fsize = args.fsize
        self.lfsize = args.lfsize
        return self.create_stream(direction,kwargs['port_id'])


# dynamic load - used for trex console or simulator
def register():
    return STLS1()



