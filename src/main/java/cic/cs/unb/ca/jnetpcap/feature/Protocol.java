package cic.cs.unb.ca.jnetpcap.feature;

import lombok.Getter;
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

    @Getter final Tcp tcp = new Tcp();
    @Getter final Udp udp = new Udp();
    @Getter final Icmp icmp  = new Icmp();
    @Getter final Ip4 ipv4  = new Ip4();
    @Getter final Ip6 ipv6  = new Ip6();
    @Getter final L2TP l2tp  = new L2TP();

    public Protocol() { }

}
