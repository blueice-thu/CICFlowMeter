package cic.cs.unb.ca.jnetpcap;

import lombok.Data;
import org.jnetpcap.packet.format.FormatUtils;

import java.util.Arrays;

@Data
public class BasicPacketInfo {

    /*  Basic Info to generate flows from packets  	*/
    private byte[] src;
    private byte[] dst;
    private int srcPort;
    private int dstPort;
    private int protocol;
    private long timeStamp;
    private long payloadBytes;
    private String flowId = null;
    /* ******************************************** */
    private boolean flagFIN = false;
    private boolean flagPSH = false;
    private boolean flagURG = false;
    private boolean flagECE = false;
    private boolean flagSYN = false;
    private boolean flagACK = false;
    private boolean flagCWR = false;
    private boolean flagRST = false;
    private int TCPWindow = 0;
    private long headerBytes;
    private int payloadPacket = 0;
    /* ******************************************** */
    private int icmpCode = -1;
    private int icmpType = -1;

    private boolean isWrongFragment = false;

    public BasicPacketInfo() { }

    public String generateFlowId() {
        boolean forward = true;

        for (int i = 0; i < this.src.length; i++) {
            if (((Byte) (this.src[i])).intValue() != ((Byte) (this.dst[i])).intValue()) {
                if (((Byte) (this.src[i])).intValue() > ((Byte) (this.dst[i])).intValue()) {
                    forward = false;
                }
                i = this.src.length;
            }
        }

        if (forward) {
            this.flowId = this.getSourceIP() + "-" + this.getDestinationIP() + "-" + this.srcPort + "-" + this.dstPort + "-" + this.protocol;
        } else {
            this.flowId = this.getDestinationIP() + "-" + this.getSourceIP() + "-" + this.dstPort + "-" + this.srcPort + "-" + this.protocol;
        }
        return this.flowId;
    }

    public String fwdFlowId() {
        this.flowId = this.getSourceIP() + "-" + this.getDestinationIP() + "-" + this.srcPort + "-" + this.dstPort + "-" + this.protocol;
        return this.flowId;
    }

    public String bwdFlowId() {
        this.flowId = this.getDestinationIP() + "-" + this.getSourceIP() + "-" + this.dstPort + "-" + this.srcPort + "-" + this.protocol;
        return this.flowId;
    }


    public int getPayloadPacket() {
        return payloadPacket += 1;
    }

    public String getSourceIP() {
        return FormatUtils.ip(this.src);
    }

    public String getDestinationIP() {
        return FormatUtils.ip(this.dst);
    }

    public byte[] getSrc() {
        return Arrays.copyOf(src, src.length);
    }

    public byte[] getDst() {
        return Arrays.copyOf(dst, dst.length);
    }

    public String getFlowId() {
        return this.flowId != null ? this.flowId : generateFlowId();
    }

    public boolean isForwardPacket(byte[] sourceIP) {
        return Arrays.equals(sourceIP, this.src);
    }

    public boolean hasFlagFIN() {
        return flagFIN;
    }

    public boolean hasFlagPSH() {
        return flagPSH;
    }

    public boolean hasFlagURG() {
        return flagURG;
    }

    public boolean hasFlagECE() {
        return flagECE;
    }

    public boolean hasFlagSYN() {
        return flagSYN;
    }

    public boolean hasFlagACK() {
        return flagACK;
    }

    public boolean hasFlagCWR() {
        return flagCWR;
    }

    public boolean hasFlagRST() {
        return flagRST;
    }

}
