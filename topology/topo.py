import argparse
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.link import TCLink

class DataCenterTopo(Topo):
    def build(self, bw=100, delay='2ms'):
        core = self.addSwitch('s1', protocols='OpenFlow13')
        host_idx = 1
        for sw_num in range(2, 5):
            aggr = self.addSwitch('s{}'.format(sw_num), protocols='OpenFlow13')
            self.addLink(core, aggr, cls=TCLink, bw=bw, delay=delay)
            for _ in range(4):
                host = self.addHost('h{}'.format(host_idx),
                                    ip='10.0.0.{}/24'.format(host_idx))
                self.addLink(aggr, host, cls=TCLink, bw=bw, delay=delay)
                host_idx += 1

def run(controller_ip='127.0.0.1', controller_port=6653):
    setLogLevel('info')
    topo = DataCenterTopo()
    net  = Mininet(topo=topo, switch=OVSSwitch, controller=None,
                   autoSetMacs=True, waitConnected=True, link=TCLink)
    net.addController('c0', controller=RemoteController,
                      ip=controller_ip, port=controller_port)
    net.start()
    info('Hosts: %s' % [h.name for h in net.hosts])
    info('Switches: %s' % [s.name for s in net.switches])
    net.pingAll()
    CLI(net)
    net.stop()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--controller', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=6653)
    args = parser.parse_args()
    run(args.controller, args.port)
