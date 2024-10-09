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
        # 默认参数
        self.fsize = 1500;
        self.lfsize = 1500;
        self.l3fwd_throughput_1 = 1;
        self.l3fwd_throughput_2 = 3;
        self.ipsec_throughput = 1;


    def create_stream (self, dir,port_id):
        # Create base packet and pad it to size
        size = self.fsize - 4; # HW will add 4 bytes ethernet FCS

        src_ip_1 = "192.81.0.3"
        src_ip_2 = "192.81.0.1"
        # src_ip_2 = "192.81.0.1"

        ipsec_src_ip = "192.81.0.1"

        # IPSec dst ip = 10.12.0.10(after DNAT is 192.82.0.1), L3 fwd dst ip = 192.82.0.2
        l3fwd_dst_ip = "192.82.0.2"
        ipsec_dst_ip = "10.12.0.10"

        l3fwd_base_pkt_1 = Ether()/IP(src=src_ip_1,dst=l3fwd_dst_ip)/UDP(dport=1234,sport=2345)
        l3fwd_base_pkt_2 = Ether()/IP(src=src_ip_2,dst=l3fwd_dst_ip)/UDP(dport=1234,sport=2345)
        ipsec_base_pkt_1 = Ether()/IP(src=ipsec_src_ip,dst=ipsec_dst_ip)/UDP(dport=1234,sport=2345)

        pad = max(0, size - len(l3fwd_base_pkt_1)) * 'x'
        pad_latency = max(0, (self.lfsize-4) - len(l3fwd_base_pkt_1)) * 'x'


        l3fwd_pkt_1 = STLPktBuilder(pkt = l3fwd_base_pkt_1/pad,vm = [])
        l3fwd_pkt_2 = STLPktBuilder(pkt = l3fwd_base_pkt_2/pad,vm = [])
        ipsec_pkt_1 = STLPktBuilder(pkt = ipsec_base_pkt_1/pad,vm = [])

        # stream1: L3 fwd 
        stream = [STLStream(packet = l3fwd_pkt_1,
                            mode = STLTXCont(pps=self.l3fwd_throughput_1 * 1000000)),
                  STLStream(packet = l3fwd_pkt_2,
                            mode = STLTXCont(pps=self.l3fwd_throughput_2 * 1000000)),
        # stream2: IPSec
                  STLStream(packet = ipsec_pkt_1,
                            mode = STLTXCont(pps=self.ipsec_throughput * 1000000)),
        # latency stream   
                  STLStream(packet = STLPktBuilder(pkt = l3fwd_base_pkt_1/pad_latency),
                            mode = STLTXCont(pps=1000),
                            flow_stats = STLFlowLatencyStats(pg_id = 12+port_id))
        ]
        return stream


    def get_streams (self, direction, tunables, **kwargs):
        parser = argparse.ArgumentParser(description='Argparser for {}'.format(os.path.basename(__file__)), 
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
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



