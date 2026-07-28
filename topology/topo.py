import argparse
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.topo import Topo
class DDoSTestbedTopo(Topo):
    """3 switches in a tree (1 root + 2 leaves), 12 hosts (6 per leaf)."""
    def build(self):
        s1 = self.addSwitch("s1", protocols="OpenFlow13")  # root / aggregation
        s2 = self.addSwitch("s2", protocols="OpenFlow13")  # leaf A
        s3 = self.addSwitch("s3", protocols="OpenFlow13")  # leaf B
        # tree edges: root -> leaves
        self.addLink(s1, s2, bw=100, delay="1ms")
        self.addLink(s1, s3, bw=100, delay="1ms")
        # 6 hosts under each leaf switch -> 12 hosts total, flat /24
        host_id = 1
        for leaf in (s2, s3):
            for _ in range(6):
                h = self.addHost(
                    f"h{host_id}",
                    ip=f"10.0.0.{host_id}/24",
                    mac=f"00:00:00:00:00:{host_id:02x}",
                )
                self.addLink(h, leaf, bw=100, delay="1ms")
                host_id += 1
def main():
    parser = argparse.ArgumentParser(description="SDN DDoS testbed topology (3-switch tree)")
    parser.add_argument("--controller", default="127.0.0.1", help="Ryu controller IP")
    parser.add_argument("--port", type=int, default=6653, help="Ryu controller OpenFlow port")
    args = parser.parse_args()
    setLogLevel("info")
    topo = DDoSTestbedTopo()
    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        link=TCLink,
        controller=None,
        autoSetMacs=False,
    )
    net.addController(
        "c0", controller=RemoteController, ip=args.controller, port=args.port
    )
    info("*** Starting network\n")
    net.start()
    info("*** Testing connectivity (pingall)\n")
    net.pingAll()
    info("*** Running CLI\n")
    CLI(net)
    info("*** Stopping network\n")
    net.stop()
if __name__ == "__main__":
    main()
