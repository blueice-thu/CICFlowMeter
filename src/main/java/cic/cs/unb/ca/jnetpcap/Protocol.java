package cic.cs.unb.ca.jnetpcap;

import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.vpn.L2TP;

public class Protocol {

    public final static int TCP = 6;
    public final static int UDP = 17;
    public final static int ICMP = 1;
    public final static int NO_PORT = -1;

    private final Tcp tcp;
    private final Udp udp;
    private final Icmp icmp;
    private final Ip4 ipv4;
    private final Ip6 ipv6;
    private final L2TP l2tp;

    public Protocol() {
        super();
        tcp = new Tcp();
        udp = new Udp();
        icmp = new Icmp();
        ipv4 = new Ip4();
        ipv6 = new Ip6();
        l2tp = new L2TP();
    }

    public Tcp getTcp() {
        return tcp;
    }

    public Udp getUdp() {
        return udp;
    }

    public Icmp getIcmp() {
        return icmp;
    }

    public Ip4 getIpv4() {
        return ipv4;
    }

    public Ip6 getIpv6() {
        return ipv6;
    }

    public L2TP getL2tp() {
        return l2tp;
    }

}
