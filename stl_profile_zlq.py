import sys

sys.path.insert(0, '/mnt/disk1/zhaolunqi/v3.03/automation/trex_control_plane/interactive')
sys.path.insert(0, '/mnt/disk1/zhaolunqi/v3.03/automation/trex_control_plane/interactive/trex/examples/stl')
sys.path.insert(0, '/mnt/disk1/zhaolunqi/v3.03/external_libs')

import stl_path
from trex.stl.api import *
from trex.utils.text_opts import format_text
import argparse
import time


def simple():
    # create client
    # verbose_level = 'high'
    c = STLClient(verbose_level="error")
    passed = True

    try:
        # connect to server
        c.connect()

        my_ports = [1]

        # prepare our ports
        c.reset(ports=my_ports)

        profile_file = "/mnt/disk1/zhaolunqi/v3.03/mystl/ip46_ratio.py"
        try:
            profile = STLProfile.load(
                profile_file, direction=0, port_id=1, ip4_ratio=1, ip6_ratio=1
            )
        except STLError as e:
            print(
                format_text(
                    "\nError while loading profile '{0}'\n".format(profile_file), "bold"
                )
            )
            print(e.brief() + "\n")
            return

        # print(profile.to_json())

        c.remove_all_streams(my_ports)

        c.add_streams(profile.get_streams(), ports=my_ports)

        c.start(ports=my_ports, mult="5mpps", duration=10)

        time.sleep(5)

        result = c.get_pgid_stats(pgid_list=[])
        print(result)

        # block until done
        c.wait_on_traffic(ports=my_ports)

    except STLError as e:
        passed = False
        print(e)

    finally:
        c.disconnect()

    if passed:
        print("\nTest has passed :-)\n")
    else:
        print("\nTest has failed :-(\n")


# run the tests
simple()
