package cic.cs.unb.ca.jnetpcap;

import cic.cs.unb.ca.jnetpcap.feature.Protocol;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapClosedException;
import org.jnetpcap.PcapHeader;
import org.jnetpcap.nio.JBuffer;
import org.jnetpcap.nio.JMemory;
import org.jnetpcap.packet.JHeader;
import org.jnetpcap.packet.JHeaderPool;
import org.jnetpcap.packet.PcapPacket;
import org.jnetpcap.protocol.lan.Ethernet;
import org.jnetpcap.protocol.network.Icmp;
import org.jnetpcap.protocol.network.Ip4;
import org.jnetpcap.protocol.network.Ip6;
import org.jnetpcap.protocol.tcpip.Tcp;
import org.jnetpcap.protocol.tcpip.Udp;
import org.jnetpcap.protocol.vpn.L2TP;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PacketReader {

    private static final Logger logger = LoggerFactory.getLogger(PacketReader.class);
    /*
     * So far,The value of the field BasicPacketInfo.id is not used
     * It doesn't matter just using a static IdGenerator for realtime PcapPacket reading
     */
    private Pcap pcapReader;
    private PcapHeader hdr;
    private JBuffer buf;
    private final boolean readIP6;
    private final boolean readIP4;
    private String file;

    public PacketReader(String filename) {
        super();
        this.readIP4 = true;
        this.readIP6 = false;
        this.config(filename);
    }

    public PacketReader(String filename, boolean readIp4, boolean readIP6) {
        super();
        this.readIP4 = readIp4;
        this.readIP6 = readIP6;
        this.config(filename);
    }

    private void config(String filename) {
        file = filename;
        StringBuilder errbuf = new StringBuilder(); // For any error msgs
        pcapReader = Pcap.openOffline(filename, errbuf);

        if (pcapReader == null) {
            logger.error("Error while opening file for capture: " + errbuf);
            System.exit(-1);
        } else {
            hdr = new PcapHeader(JMemory.POINTER);
            buf = new JBuffer(JMemory.POINTER);
        }
    }

    public static BasicPacketInfo getBasicPacketInfo(PcapPacket packet, boolean readIP4, boolean readIP6) {
        BasicPacketInfo packetInfo = null;

        if (readIP4) {
            packetInfo = getIpv4Info(packet);
        }
        if (packetInfo == null && readIP6) {
            packetInfo = getIpv6Info(packet);
        }
        if (packetInfo == null) {
            packetInfo = getVPNInfo(packet, readIP4, readIP6);
        }
        if (packetInfo == null) {
            logger.error("GetBasicPacketInfo error");
        }

        return packetInfo;
    }

    public BasicPacketInfo nextPacket() {
        PcapPacket packet;
        BasicPacketInfo packetInfo = null;
        try {
            if (pcapReader.nextEx(hdr, buf) == Pcap.NEXT_EX_OK) {
                packet = new PcapPacket(hdr, buf);
                packet.scan(Ethernet.ID);
                packetInfo = getBasicPacketInfo(packet, this.readIP4, this.readIP6);
            } else {
                throw new PcapClosedException();
            }
        } catch (PcapClosedException e) {
            logger.debug("Read All packets on {}", file);
            throw e;
        } catch (Exception ex) {
            logger.debug(ex.getMessage());
        }
        return packetInfo;
    }

    private static BasicPacketInfo getIpv4Info(PcapPacket packet) {
        BasicPacketInfo packetInfo = null;
        Protocol protocol = new Protocol();
        try {

            if (packet.hasHeader(protocol.getIpv4())) {
                packetInfo = new BasicPacketInfo();
                packetInfo.setSrc(protocol.getIpv4().source());
                packetInfo.setDst(protocol.getIpv4().destination());
                packetInfo.setWrongFragment(!protocol.getIpv4().isChecksumValid());

                packetInfo.setTimeStamp(packet.getCaptureHeader().timestampInMicros());

                if (packet.hasHeader(protocol.getTcp())) {
                    Tcp tcp = protocol.getTcp();
                    packetInfo.setProtocol(Protocol.TCP);
                    packetInfo.setTCPWindow(tcp.window());
                    packetInfo.setSrcPort(tcp.source());
                    packetInfo.setDstPort(tcp.destination());
                    packetInfo.setFlagFIN(tcp.flags_FIN());
                    packetInfo.setFlagPSH(tcp.flags_PSH());
                    packetInfo.setFlagURG(tcp.flags_URG());
                    packetInfo.setFlagSYN(tcp.flags_SYN());
                    packetInfo.setFlagACK(tcp.flags_ACK());
                    packetInfo.setFlagECE(tcp.flags_ECE());
                    packetInfo.setFlagCWR(tcp.flags_CWR());
                    packetInfo.setFlagRST(tcp.flags_RST());
                    packetInfo.setPayloadLength(tcp.getPayloadLength());
                    packetInfo.setHeaderLength(tcp.getHeaderLength());
                } else if (packet.hasHeader(protocol.getUdp())) {
                    Udp udp = protocol.getUdp();
                    packetInfo.setProtocol(Protocol.UDP);
                    packetInfo.setSrcPort(udp.source());
                    packetInfo.setDstPort(udp.destination());
                    packetInfo.setPayloadLength(udp.getPayloadLength());
                    packetInfo.setHeaderLength(udp.getHeaderLength());
                } else if (packet.hasHeader(protocol.getIcmp())) {
                    Icmp icmp = protocol.getIcmp();
                    packetInfo.setProtocol(Protocol.ICMP);
                    packetInfo.setSrcPort(Protocol.NO_PORT);
                    packetInfo.setDstPort(Protocol.NO_PORT);
                    packetInfo.setIcmpCode(icmp.code());
                    packetInfo.setIcmpType(icmp.type());
                } else {
                    /*logger.debug("other packet Ethernet -> {}"+  packet.hasHeader(new Ethernet()));
					logger.debug("other packet Html     -> {}"+  packet.hasHeader(new Html()));
					logger.debug("other packet Http     -> {}"+  packet.hasHeader(new Http()));
					logger.debug("other packet SLL      -> {}"+  packet.hasHeader(new SLL()));
					logger.debug("other packet L2TP     -> {}"+  packet.hasHeader(new L2TP()));
					logger.debug("other packet Sctp     -> {}"+  packet.hasHeader(new Sctp()));
					logger.debug("other packet PPP      -> {}"+  packet.hasHeader(new PPP()));*/
                    int headerCount = packet.getHeaderCount();
                    for (int i = 0; i < headerCount; i++) {
                        JHeader header = JHeaderPool.getDefault().getHeader(i);
                        //JHeader hh = packet.getHeaderByIndex(i, header);
                        //logger.debug("getIpv4Info: {} --description: {} ",header.getName(),header.getDescription());
                    }
                }
            }
        } catch (Exception e) {
            /*
             * BufferUnderflowException while decoding header
             * havn't fixed, so do not e.printStackTrace()
             */
            //e.printStackTrace();
			packet.scan(Ip4.ID);
			String errormsg = "";
			errormsg+=e.getMessage()+"\n";
			//errormsg+=packet.getHeader(new Ip4())+"\n";
			errormsg+="********************************************************************************"+"\n";
			errormsg+=packet.toHexdump()+"\n";
			logger.error(errormsg);
			return null;
        }

        return packetInfo;
    }

    private static BasicPacketInfo getIpv6Info(PcapPacket packet) {
        BasicPacketInfo packetInfo = null;
        Protocol protocol = new Protocol();
        try {
            if (packet.hasHeader(protocol.getIpv6())) {
                packetInfo = new BasicPacketInfo();
                packetInfo.setSrc(protocol.getIpv6().source());
                packetInfo.setDst(protocol.getIpv6().destination());
                packetInfo.setTimeStamp(packet.getCaptureHeader().timestampInMillis());

                if (packet.hasHeader(protocol.getTcp())) {
                    packetInfo.setSrcPort(protocol.getTcp().source());
                    packetInfo.setDstPort(protocol.getTcp().destination());
                    packetInfo.setPayloadLength(protocol.getTcp().getPayloadLength());
                    packetInfo.setHeaderLength(protocol.getTcp().getHeaderLength());
                    packetInfo.setProtocol(6);
                } else if (packet.hasHeader(protocol.getUdp())) {
                    packetInfo.setSrcPort(protocol.getUdp().source());
                    packetInfo.setDstPort(protocol.getUdp().destination());
                    packetInfo.setPayloadLength(protocol.getUdp().getPayloadLength());
                    packetInfo.setHeaderLength(protocol.getUdp().getHeaderLength());
                    packetInfo.setProtocol(17);
                }
            }
        } catch (Exception e) {
            /*
             * BufferUnderflowException while decoding header
             * havn't fixed, so do not e.printStackTrace()
             */
            //e.printStackTrace();
            packet.scan(Ip6.ID);
            String errormsg = "";
            errormsg+=e.getMessage()+"\n";
            //errormsg+=packet.getHeader(new Ip6())+"\n";
            errormsg+="********************************************************************************"+"\n";
            errormsg+=packet.toHexdump()+"\n";
            logger.error(errormsg);
            //System.exit(-1);
            return null;
        }

        return packetInfo;
    }

    private static BasicPacketInfo getVPNInfo(PcapPacket packet, boolean readIP4, boolean readIP6) {
        BasicPacketInfo packetInfo = null;
        Protocol protocol = new Protocol();
        try {
            packet.scan(L2TP.ID);

            if (packet.hasHeader(protocol.getL2tp())) {
                if (readIP4) {
                    packet.scan(Ip4.ID);
                    packetInfo = getIpv4Info(packet);
                }
                if (packetInfo == null && readIP6) {
                    packet.scan(Ip6.ID);
                    packetInfo = getIpv6Info(packet);
                }

            }
        } catch (Exception e) {
            /*
             * BufferUnderflowException while decoding header
             * havn't fixed, so do not e.printStackTrace()
             */
            //e.printStackTrace();
            packet.scan(L2TP.ID);
            String errormsg = "";
            errormsg+=e.getMessage()+"\n";
            //errormsg+=packet.getHeader(new L2TP())+"\n";
            errormsg+="********************************************************************************"+"\n";
            errormsg+=packet.toHexdump()+"\n";
            logger.error(errormsg);
            return null;
        }

        return packetInfo;
    }
}
