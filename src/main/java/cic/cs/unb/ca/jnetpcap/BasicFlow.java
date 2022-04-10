package cic.cs.unb.ca.jnetpcap;

import cic.cs.unb.ca.jnetpcap.feature.FlowState;
import cic.cs.unb.ca.jnetpcap.feature.Protocol;
import cic.cs.unb.ca.jnetpcap.feature.ServiceType;
import org.apache.commons.math3.stat.descriptive.SummaryStatistics;
import org.jnetpcap.packet.format.FormatUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;

import static cic.cs.unb.ca.jnetpcap.Utils.convertMilliseconds2String;

public class BasicFlow {

    private final static String separator = ",";
    private final long UNINITIALIZED = 0L;
    private final SummaryStatistics fwdPktStats = new SummaryStatistics();
    private final SummaryStatistics bwdPktStats = new SummaryStatistics();
    private List<BasicPacketInfo> forward = new ArrayList<>();
    private List<BasicPacketInfo> backward = new ArrayList<>();

    private BasicPacketInfo firstPacket = null;

    private long fwdBytes = 0L;
    private long bwdBytes = 0L;
    private long fwdHeaderBytes = 0L;
    private long bwdHeaderBytes = 0L;

    private boolean isBidirectional;

    private final HashMap<String, MutableInt> flagCounts = new HashMap<>();

    private int fFIN_cnt = 0;
    private int bFIN_cnt = 0;

    private long fwdPacketsWithData = 0L;
    private long minFwdSegmentSize = Long.MAX_VALUE;
    private int fwdInitWindow = -1;
    private int bwdInitWindow = -1;
    private int fwdInitWinBytes = 0;
    private int bwdInitWinBytes = 0;

    private byte[] src = null;
    private byte[] dst = null;
    private int srcPort;
    private int dstPort;
    private int protocol;

    private long flowStartTime;
    private long startActiveTime = 0L;
    private long endActiveTime = 0L;

    private String flowId = null;

    private final SummaryStatistics flowIAT = new SummaryStatistics();
    private final SummaryStatistics forwardIAT = new SummaryStatistics();
    private final SummaryStatistics backwardIAT = new SummaryStatistics();
    private final SummaryStatistics flowLengthStats = new SummaryStatistics();
    private final SummaryStatistics flowActive = new SummaryStatistics();
    private final SummaryStatistics flowIdle = new SummaryStatistics();

    private long flowLastSeenTime = UNINITIALIZED;
    private long fwdLastSeenTime = UNINITIALIZED;
    private long bwdLastSeenTime = UNINITIALIZED;
    private final long activityTimeout;
    private long sfLastPacketTS = -1;
    private int sfCount = 0;
    private long sfAcHelper = -1;

    private long fwdBulkDuration = 0;
    private long fwdBulkPacketCount = 0;
    private long fwdBulkSizeTotal = 0;
    private long fwdBulkStateCount = 0;
    private long fwdBulkPacketCountHelper = 0;
    private long fwdBulkStartHelper = 0;
    private long fwdBulkSizeHelper = 0;
    private long fwdLastBulkTS = 0;
    private long bwdBulkDuration = 0;
    private long bwdBulkPacketCount = 0;
    private long bwdBulkSizeTotal = 0;
    private long bwdBulkStateCount = 0;
    private long bwdBulkPacketCountHelper = 0;
    private long bwdBulkStartHelper = 0;
    private long bwdBulkSizeHelper = 0;
    private long bwdLastBulkTS = 0;

    private long wrongFragmentCount = 0;
    private FlowState flowState = FlowState.INIT;

    private final String[] flagKeys = new String[] {"FIN", "SYN", "RST", "PSH", "ACK", "URG", "CWR", "ECE", "PSH_FWD", "PSH_BWD", "UGR_FWD", "URG_BWD"};

    public BasicFlow(boolean isBidirectional, BasicPacketInfo packet, long activityTimeout) {
        super();
        this.activityTimeout = activityTimeout;
        this.isBidirectional = isBidirectional;
        for (String flag: flagKeys) {
            flagCounts.put(flag, new MutableInt());
        }
        initFlow(packet);
        addPacket(packet);
    }

    private void initFlow(BasicPacketInfo packet) {
        firstPacket = packet;
        flowStartTime = packet.getTimeStamp();
        flowLastSeenTime = packet.getTimeStamp();
        startActiveTime = packet.getTimeStamp();
        endActiveTime = packet.getTimeStamp();
        src = packet.getSrc();
        srcPort = packet.getSrcPort();
        dst = packet.getDst();
        dstPort = packet.getDstPort();
        protocol = packet.getProtocol();
        flowId = packet.getFlowId();
        fwdInitWindow = packet.getTCPWindow();
    }

    static class MutableInt {
        public int value = 0; // note that we start at 1 since we're counting
        public void increment() {
            ++value;
        }
    }

    private boolean isForwardPacket(BasicPacketInfo packet) {
        return Arrays.equals(this.src, packet.getSrc());
    }

    public void addPacket(BasicPacketInfo packet) {
        updateFlowBulk(packet);
        detectUpdateSubflows(packet);
        checkFlags(packet);
        updateFlowState(packet);

        long currentTimestamp = packet.getTimeStamp();

        if (isForwardPacket(packet) || !this.isBidirectional) {
            forward.add(packet);
            fwdPktStats.addValue((double) packet.getPayloadBytes());
            fwdHeaderBytes += packet.getHeaderBytes();
            fwdBytes += packet.getPayloadBytes();
            minFwdSegmentSize = Math.min(packet.getHeaderBytes(), minFwdSegmentSize);

            if (packet.getPayloadBytes() >= 1)
                fwdPacketsWithData++;
            if (packet.getTCPWindow() == fwdInitWindow)
                fwdInitWinBytes += packet.getPayloadBytes();
            else
                fwdInitWindow = -2; // Should not be used forever

            if (forward.size() > 1)
                forwardIAT.addValue(currentTimestamp - fwdLastSeenTime);

            fwdLastSeenTime = currentTimestamp;
        } else {
            if (bwdInitWindow == -1) { // First backward packet
                bwdInitWindow = packet.getTCPWindow();
            }
            backward.add(packet);
            bwdPktStats.addValue((double) packet.getPayloadBytes());
            bwdInitWinBytes = packet.getTCPWindow();
            bwdHeaderBytes += packet.getHeaderBytes();
            bwdBytes += packet.getPayloadBytes();

            if (bwdInitWindow == -1)
                bwdInitWinBytes = packet.getTCPWindow();
            if (packet.getTCPWindow() == bwdInitWindow)
                bwdInitWinBytes += packet.getPayloadBytes();
            else
                bwdInitWindow = -2; // Should not be used forever

            if (backward.size() > 1)
                backwardIAT.addValue(currentTimestamp - bwdLastSeenTime);

            bwdLastSeenTime = currentTimestamp;
        }

        if (getPacketCount() > 1)
            flowIAT.addValue(packet.getTimeStamp() - flowLastSeenTime);
        flowLengthStats.addValue((double) packet.getPayloadBytes());
        flowLastSeenTime = packet.getTimeStamp();
    }

    public double getfPktsPerSecond() {
        long duration = this.flowLastSeenTime - this.flowStartTime;
        if (duration > 0) {
            return (this.forward.size() / ((double) duration / 1000000L));
        } else
            return 0;
    }

    public double getbPktsPerSecond() {
        long duration = this.flowLastSeenTime - this.flowStartTime;
        if (duration > 0) {
            return (this.backward.size() / ((double) duration / 1000000L));
        } else
            return 0;
    }

    public double getDownUpRatio() {
        if (this.forward.size() > 0) {
            return this.backward.size() * 1.0 / this.forward.size();
        }
        return 0;
    }

    public double fAvgSegmentSize() {
        if (this.forward.size() != 0)
            return (this.fwdPktStats.getSum() / (double) this.forward.size());
        return 0;
    }

    public double bAvgSegmentSize() {
        if (this.backward.size() != 0)
            return (this.bwdPktStats.getSum() / (double) this.backward.size());
        return 0;
    }

    public void checkFlags(BasicPacketInfo packet) {
        boolean isForwardPacket = isForwardPacket(packet);
        if (packet.hasFlagFIN()) {
            flagCounts.get("FIN").increment();
        }
        if (packet.hasFlagSYN()) {
            flagCounts.get("SYN").increment();
        }
        if (packet.hasFlagRST()) {
            flagCounts.get("RST").increment();
        }
        if (packet.hasFlagPSH()) {
            flagCounts.get("PSH").increment();
            if (isForwardPacket)
                flagCounts.get("PSH_FWD").increment();
            else
                flagCounts.get("PSH_BWD").increment();
        }
        if (packet.hasFlagACK()) {
            flagCounts.get("ACK").increment();
        }
        if (packet.hasFlagURG()) {
            flagCounts.get("URG").increment();
            if (isForwardPacket)
                flagCounts.get("UGR_FWD").increment();
            else
                flagCounts.get("URG_BWD").increment();
        }
        if (packet.hasFlagCWR()) {
            flagCounts.get("CWR").increment();
        }
        if (packet.hasFlagECE()) {
            flagCounts.get("ECE").increment();
        }
        if (packet.isWrongFragment()) {
            wrongFragmentCount++;
        }
    }

    public long getSflow_fbytes() {
        if (sfCount <= 0) return 0;
        return this.fwdBytes / sfCount;
    }

    public long getSflow_fpackets() {
        if (sfCount <= 0) return 0;
        return this.forward.size() / sfCount;
    }

    public long getSflow_bbytes() {
        if (sfCount <= 0) return 0;
        return this.bwdBytes / sfCount;
    }

    public long getSflow_bpackets() {
        if (sfCount <= 0) return 0;
        return this.backward.size() / sfCount;
    }

    void detectUpdateSubflows(BasicPacketInfo packet) {
        if (sfLastPacketTS == -1) {
            sfLastPacketTS = packet.getTimeStamp();
            sfAcHelper = packet.getTimeStamp();
        }
        //System.out.print(" - "+(packet.timeStamp - sfLastPacketTS));
        if (((packet.getTimeStamp() - sfLastPacketTS) / (double) 1000000) > 1.0) {
            sfCount++;
            long lastSFduration = packet.getTimeStamp() - sfAcHelper;
            updateActiveIdleTime(packet.getTimeStamp(), this.activityTimeout);
            sfAcHelper = packet.getTimeStamp();
        }

        sfLastPacketTS = packet.getTimeStamp();
    }

    public void updateFlowBulk(BasicPacketInfo packet) {
        if (isForwardPacket(packet)) {
            updateForwardBulk(packet, bwdLastBulkTS);
        } else {
            updateBackwardBulk(packet, fwdLastBulkTS);
        }
    }

    public void updateFlowState(BasicPacketInfo packet) {
        if (this.protocol == Protocol.TCP) {
            boolean isForward = Arrays.equals(this.src, packet.getSrc());
            switch (this.flowState) {
                case INIT:
                    if (packet.hasFlagSYN() && packet.hasFlagACK())
                        flowState = FlowState.S4;
                    else if (packet.hasFlagSYN())
                        flowState = FlowState.S1;
                    else
                        flowState = FlowState.OTH;
                    break;

                case S0:
                    if (isForward) {
                        if (packet.hasFlagRST())
                            flowState = FlowState.RSTOS0;
                        else if (packet.hasFlagFIN())
                            flowState = FlowState.SH;
                    }
                    else { // from responder
                        if (packet.hasFlagRST())
                            flowState = FlowState.REJ;
                        else if (packet.hasFlagSYN() && packet.hasFlagACK())
                            flowState = FlowState.S1;
                    }
                    break;

                case S4:
                    if (isForward) {
                        if (packet.hasFlagRST())
                            flowState = FlowState.RSTRH;
                        else if (packet.hasFlagFIN())
                            flowState = FlowState.SHR;
                    }
                    break;

                case S1:
                    if (isForward) {
                        if (packet.hasFlagRST())
                            flowState = FlowState.RSTO;
                        else if (packet.hasFlagACK())
                            flowState = FlowState.ESTAB;
                    }
                    else { // responder
                        if (packet.hasFlagRST())
                            flowState = FlowState.RSTR;
                    }
                    break;

                case ESTAB:
                    if (isForward) {
                        if (packet.hasFlagRST())
                            flowState = FlowState.RSTO;
                        else if (packet.hasFlagFIN())
                            flowState = FlowState.S2;
                    }
                    else { // responder
                        if (packet.hasFlagRST())
                            flowState = FlowState.RSTR;
                        else if (packet.hasFlagFIN())
                            flowState = FlowState.S3;
                    }
                    break;

                case S2:
                    if (isForward) {
                        if (packet.hasFlagRST())
                            flowState = FlowState.RSTO;
                    }
                    else { // responder
                        if (packet.hasFlagRST())
                            flowState = FlowState.RSTR;
                        else if (packet.hasFlagFIN())
                            flowState = FlowState.S2F;
                    }
                    break;

                case S3:
                    if (isForward) {
                        if (packet.hasFlagRST())
                            flowState = FlowState.RSTO;
                        else if (packet.hasFlagFIN())
                            flowState = FlowState.S3F;
                    }
                    else { // responder
                        if (packet.hasFlagRST())
                            flowState = FlowState.RSTR;
                    }
                    break;

                case S2F:
                    if (isForward) {
                        if (packet.hasFlagRST())
                            flowState = FlowState.RSTO;
                        else if (packet.hasFlagACK())
                            flowState = FlowState.SF;
                    }
                    else { // responder
                        if (packet.hasFlagRST())
                            flowState = FlowState.RSTR;
                    }
                    break;

                case S3F:
                    if (isForward) {
                        if (packet.hasFlagRST())
                            flowState = FlowState.RSTO;
                    }
                    else { // responder
                        if (packet.hasFlagRST())
                            flowState = FlowState.RSTR;
                        else if (packet.hasFlagACK())
                            flowState = FlowState.SF;
                    }
                    break;

                default:
                    break;
            }
        } else {
            flowState = FlowState.SF;
        }
    }

    public int getFlowState() {
        FlowState state = flowState;
        switch (state) {
            case ESTAB:
                state = FlowState.S1;
            break;

            case S4:
                state = FlowState.OTH;
            break;

            case S2F:
                state = FlowState.S2;
            break;

            case S3F:
                state = FlowState.S3;
            break;
        }
        return state.ordinal();
    }

    public void updateForwardBulk(BasicPacketInfo packet, long tsOflastBulkInOther) {

        long size = packet.getPayloadBytes();
        if (tsOflastBulkInOther > fwdBulkStartHelper) fwdBulkStartHelper = 0;
        if (size <= 0) return;

        packet.getPayloadPacket();

        if (fwdBulkStartHelper == 0) {
            fwdBulkStartHelper = packet.getTimeStamp();
            fwdBulkPacketCountHelper = 1;
            fwdBulkSizeHelper = size;
            fwdLastBulkTS = packet.getTimeStamp();
        } //possible bulk
        else {
            // Too much idle time?
            if (((packet.getTimeStamp() - fwdLastBulkTS) / (double) 1000000) > 1.0) {
                fwdBulkStartHelper = packet.getTimeStamp();
                fwdLastBulkTS = packet.getTimeStamp();
                fwdBulkPacketCountHelper = 1;
                fwdBulkSizeHelper = size;
            }// Add to bulk
            else {
                fwdBulkPacketCountHelper += 1;
                fwdBulkSizeHelper += size;
                //New bulk
                if (fwdBulkPacketCountHelper == 4) {
                    fwdBulkStateCount += 1;
                    fwdBulkPacketCount += fwdBulkPacketCountHelper;
                    fwdBulkSizeTotal += fwdBulkSizeHelper;
                    fwdBulkDuration += packet.getTimeStamp() - fwdBulkStartHelper;
                } //Continuation of existing bulk
                else if (fwdBulkPacketCountHelper > 4) {
                    fwdBulkPacketCount += 1;
                    fwdBulkSizeTotal += size;
                    fwdBulkDuration += packet.getTimeStamp() - fwdLastBulkTS;
                }
                fwdLastBulkTS = packet.getTimeStamp();
            }
        }
    }

    public void updateBackwardBulk(BasicPacketInfo packet, long tsOflastBulkInOther) {
		/*bAvgBytesPerBulk =0;
		bbulkSizeTotal=0;
		bbulkStateCount=0;*/
        long size = packet.getPayloadBytes();
        if (tsOflastBulkInOther > bwdBulkStartHelper) bwdBulkStartHelper = 0;
        if (size <= 0) return;

        packet.getPayloadPacket();

        if (bwdBulkStartHelper == 0) {
            bwdBulkStartHelper = packet.getTimeStamp();
            bwdBulkPacketCountHelper = 1;
            bwdBulkSizeHelper = size;
            bwdLastBulkTS = packet.getTimeStamp();
        } //possible bulk
        else {
            // Too much idle time?
            if (((packet.getTimeStamp() - bwdLastBulkTS) / (double) 1000000) > 1.0) {
                bwdBulkStartHelper = packet.getTimeStamp();
                bwdLastBulkTS = packet.getTimeStamp();
                bwdBulkPacketCountHelper = 1;
                bwdBulkSizeHelper = size;
            }// Add to bulk
            else {
                bwdBulkPacketCountHelper += 1;
                bwdBulkSizeHelper += size;
                //New bulk
                if (bwdBulkPacketCountHelper == 4) {
                    bwdBulkStateCount += 1;
                    bwdBulkPacketCount += bwdBulkPacketCountHelper;
                    bwdBulkSizeTotal += bwdBulkSizeHelper;
                    bwdBulkDuration += packet.getTimeStamp() - bwdBulkStartHelper;
                } //Continuation of existing bulk
                else if (bwdBulkPacketCountHelper > 4) {
                    bwdBulkPacketCount += 1;
                    bwdBulkSizeTotal += size;
                    bwdBulkDuration += packet.getTimeStamp() - bwdLastBulkTS;
                }
                bwdLastBulkTS = packet.getTimeStamp();
            }
        }

    }

    public double fbulkDurationInSecond() {
        return fwdBulkDuration / (double) 1000000;
    }


    //Client average bytes per bulk
    public long fAvgBytesPerBulk() {
        if (fwdBulkStateCount != 0)
            return (fwdBulkSizeTotal / fwdBulkStateCount);
        return 0;
    }


    //Client average packets per bulk
    public long fAvgPacketsPerBulk() {
        if (fwdBulkStateCount != 0)
            return (fwdBulkPacketCount / fwdBulkStateCount);
        return 0;
    }


    //Client average bulk rate
    public long fAvgBulkRate() {
        if (fwdBulkDuration != 0)
            return (long) (fwdBulkSizeTotal / this.fbulkDurationInSecond());
        return 0;
    }


    //new features server
    public long bbulkPacketCount() {
        return bwdBulkPacketCount;
    }

    public long bbulkStateCount() {
        return bwdBulkStateCount;
    }

    public long bbulkSizeTotal() {
        return bwdBulkSizeTotal;
    }

    public long bbulkDuration() {
        return bwdBulkDuration;
    }

    public double bbulkDurationInSecond() {
        return bwdBulkDuration / (double) 1000000;
    }

    //Server average bytes per bulk
    public long bAvgBytesPerBulk() {
        if (this.bbulkStateCount() != 0)
            return (this.bbulkSizeTotal() / this.bbulkStateCount());
        return 0;
    }

    //Server average packets per bulk
    public long bAvgPacketsPerBulk() {
        if (this.bbulkStateCount() != 0)
            return (this.bbulkPacketCount() / this.bbulkStateCount());
        return 0;
    }

    //Server average bulk rate
    public long bAvgBulkRate() {
        if (this.bbulkDuration() != 0)
            return (long) (this.bbulkSizeTotal() / this.bbulkDurationInSecond());
        return 0;
    }

    ////////////////////////////


    public void updateActiveIdleTime(long currentTime, long threshold) {
        if ((currentTime - this.endActiveTime) > threshold) {
            if ((this.endActiveTime - this.startActiveTime) > 0) {
                this.flowActive.addValue(this.endActiveTime - this.startActiveTime);
            }
            this.flowIdle.addValue(currentTime - this.endActiveTime);
            this.startActiveTime = currentTime;
        }
        this.endActiveTime = currentTime;
    }

    public void endActiveIdleTime(long currentTime, long threshold, long flowTimeOut, boolean isFlagEnd) {

        if ((this.endActiveTime - this.startActiveTime) > 0) {
            this.flowActive.addValue(this.endActiveTime - this.startActiveTime);
        }

        if (!isFlagEnd && ((flowTimeOut - (this.endActiveTime - this.flowStartTime)) > 0)) {
            this.flowIdle.addValue(flowTimeOut - (this.endActiveTime - this.flowStartTime));
        }
    }

    public int getPacketCount() {
        return forward.size() + backward.size();
    }

    public List<BasicPacketInfo> getForward() {
        return new ArrayList<>(forward);
    }

    public void setForward(List<BasicPacketInfo> forward) {
        this.forward = forward;
    }

    public List<BasicPacketInfo> getBackward() {
        return new ArrayList<>(backward);
    }

    public void setBackward(List<BasicPacketInfo> backward) {
        this.backward = backward;
    }

    public boolean isBidirectional() {
        return isBidirectional;
    }

    public BasicPacketInfo getFirstPacket() {
        return firstPacket;
    }

    public void setBidirectional(boolean isBidirectional) {
        this.isBidirectional = isBidirectional;
    }

    public byte[] getSrc() {
        return Arrays.copyOf(src, src.length);
    }

    public void setSrc(byte[] src) {
        this.src = src;
    }

    public byte[] getDst() {
        return Arrays.copyOf(dst, dst.length);
    }

    public void setDst(byte[] dst) {
        this.dst = dst;
    }

    public int getSrcPort() {
        return srcPort;
    }

    public void setSrcPort(int srcPort) {
        this.srcPort = srcPort;
    }

    public int getDstPort() {
        return dstPort;
    }

    public void setDstPort(int dstPort) {
        this.dstPort = dstPort;
    }

    public int getProtocol() {
        return protocol;
    }

    public void setProtocol(int protocol) {
        this.protocol = protocol;
    }

    public String getProtocolStr() {
        switch (this.protocol) {
            case Protocol.TCP:
                return "TCP";
            case Protocol.UDP:
                return "UDP";
            case Protocol.ICMP:
                return "ICMP";
        }
        return "UNKNOWN";
    }

    public long getFlowStartTime() {
        return flowStartTime;
    }

    public void setFlowStartTime(long flowStartTime) {
        this.flowStartTime = flowStartTime;
    }

    public String getFlowId() {
        return flowId;
    }

    public void setFlowId(String flowId) {
        this.flowId = flowId;
    }

    public long getLastSeen() {
        return flowLastSeenTime;
    }

    public void setLastSeen(long lastSeen) {
        this.flowLastSeenTime = lastSeen;
    }

    public long getStartActiveTime() {
        return startActiveTime;
    }

    public void setStartActiveTime(long startActiveTime) {
        this.startActiveTime = startActiveTime;
    }

    public long getEndActiveTime() {
        return endActiveTime;
    }

    public void setEndActiveTime(long endActiveTime) {
        this.endActiveTime = endActiveTime;
    }

    public String getSrcIP() {
        return FormatUtils.ip(src);
    }

    public String getDstIP() {
        return FormatUtils.ip(dst);
    }

    public long getFlowDuration() {
        return flowLastSeenTime - flowStartTime;
    }

    public long getTotalFwdPackets() {
        return fwdPktStats.getN();
    }

    public long getTotalBackwardPackets() {
        return bwdPktStats.getN();
    }

    public double getTotalLengthofFwdPackets() {
        return fwdPktStats.getSum();
    }

    public double getTotalLengthofBwdPackets() {
        return bwdPktStats.getSum();
    }

    public double getFwdPacketLengthMax() {
        return (fwdPktStats.getN() > 0L) ? fwdPktStats.getMax() : 0;
    }

    public double getFwdPacketLengthMin() {
        return (fwdPktStats.getN() > 0L) ? fwdPktStats.getMin() : 0;
    }

    public double getFwdPacketLengthMean() {
        return (fwdPktStats.getN() > 0L) ? fwdPktStats.getMean() : 0;
    }

    public double getFwdPacketLengthStd() {
        return (fwdPktStats.getN() > 0L) ? fwdPktStats.getStandardDeviation() : 0;
    }

    public double getBwdPacketLengthMax() {
        return (bwdPktStats.getN() > 0L) ? bwdPktStats.getMax() : 0;
    }

    public double getBwdPacketLengthMin() {
        return (bwdPktStats.getN() > 0L) ? bwdPktStats.getMin() : 0;
    }

    public double getBwdPacketLengthMean() {
        return (bwdPktStats.getN() > 0L) ? bwdPktStats.getMean() : 0;
    }

    public double getBwdPacketLengthStd() {
        return (bwdPktStats.getN() > 0L) ? bwdPktStats.getStandardDeviation() : 0;
    }

    public double getFlowBytesPerSec() {
        //flow duration is in microseconds, therefore packets per seconds = packets / (duration/1000000)
        return ((double) (fwdBytes + bwdBytes)) / ((double) getFlowDuration() / 1000000L);
    }

    public double getFlowPacketsPerSec() {
        return ((double) getPacketCount()) / ((double) getFlowDuration() / 1000000L);
    }

    public SummaryStatistics getFlowIAT() {
        return flowIAT;
    }

    public double getFwdIATTotal() {
        return (forward.size() > 1) ? forwardIAT.getSum() : 0;
    }

    public double getFwdIATMean() {
        return (forward.size() > 1) ? forwardIAT.getMean() : 0;
    }

    public double getFwdIATStd() {
        return (forward.size() > 1) ? forwardIAT.getStandardDeviation() : 0;
    }

    public double getFwdIATMax() {
        return (forward.size() > 1) ? forwardIAT.getMax() : 0;
    }

    public double getFwdIATMin() {
        return (forward.size() > 1) ? forwardIAT.getMin() : 0;
    }

    public double getBwdIATTotal() {
        return (backward.size() > 1) ? backwardIAT.getSum() : 0;
    }

    public double getBwdIATMean() {
        return (backward.size() > 1) ? backwardIAT.getMean() : 0;
    }

    public double getBwdIATStd() {
        return (backward.size() > 1) ? backwardIAT.getStandardDeviation() : 0;
    }

    public double getBwdIATMax() {
        return (backward.size() > 1) ? backwardIAT.getMax() : 0;
    }

    public double getBwdIATMin() {
        return (backward.size() > 1) ? backwardIAT.getMin() : 0;
    }

    public int getFwdFINFlags() {
        return fFIN_cnt;
    }

    public int getBwdFINFlags() {
        return bFIN_cnt;
    }

    public int setFwdFINFlags() {
        fFIN_cnt++;
        return fFIN_cnt;
    }

    public int setBwdFINFlags() {
        bFIN_cnt++;
        return bFIN_cnt;
    }

    public long getFwdHeaderLength() {
        return fwdHeaderBytes;
    }

    public long getBwdHeaderLength() {
        return bwdHeaderBytes;
    }

    public double getMinPacketLength() {
        return (forward.size() > 0 || backward.size() > 0) ? flowLengthStats.getMin() : 0;
    }

    public double getMaxPacketLength() {
        return (forward.size() > 0 || backward.size() > 0) ? flowLengthStats.getMax() : 0;
    }

    public double getPacketLengthMean() {
        return (forward.size() > 0 || backward.size() > 0) ? flowLengthStats.getMean() : 0;
    }

    public double getPacketLengthStd() {
        return (forward.size() > 0 || backward.size() > 0) ? flowLengthStats.getStandardDeviation() : 0;
    }

    public double getPacketLengthVariance() {
        return (forward.size() > 0 || backward.size() > 0) ? flowLengthStats.getVariance() : 0;
    }

    public int getFlagCount(String key) {
        return flagCounts.get(key).value;
    }

    public int getFwdInitWinBytes() {
        return fwdInitWinBytes;
    }

    public int getBwdInitWinBytes() {
        return bwdInitWinBytes;
    }

    public long getFwdPacketsWithData() {
        return fwdPacketsWithData;
    }

    public long getmin_seg_size_forward() {
        return minFwdSegmentSize;
    }

    public double getActiveMean() {
        return (flowActive.getN() > 0) ? flowActive.getMean() : 0;
    }

    public double getActiveStd() {
        return (flowActive.getN() > 0) ? flowActive.getStandardDeviation() : 0;
    }

    public double getActiveMax() {
        return (flowActive.getN() > 0) ? flowActive.getMax() : 0;
    }

    public double getActiveMin() {
        return (flowActive.getN() > 0) ? flowActive.getMin() : 0;
    }

    public double getIdleMean() {
        return (flowIdle.getN() > 0) ? flowIdle.getMean() : 0;
    }

    public double getIdleStd() {
        return (flowIdle.getN() > 0) ? flowIdle.getStandardDeviation() : 0;
    }

    public double getIdleMax() {
        return (flowIdle.getN() > 0) ? flowIdle.getMax() : 0;
    }

    public double getIdleMin() {
        return (flowIdle.getN() > 0) ? flowIdle.getMin() : 0;
    }

    public int getLand() {
        if (getProtocol() != Protocol.TCP && getProtocol() != Protocol.UDP) return 0;
        return (getSrcIP().equals(getDstIP()) && getSrcPort() == getDstPort()) ? 1 : 0;
    }

    public int getService() {
        return ServiceType.getService(this).ordinal();
    }

    public String getLabel() {
        //the original is "|". I think it should be "||" need to check,
		/*if(FormatUtils.ip(src).equals("147.32.84.165") || FormatUtils.ip(dst).equals("147.32.84.165")){
			return "BOTNET";													
		}
		else{
			return "BENIGN";
		}*/
        return "NeedManualLabel";
    }

    private void addZeros(StringBuilder dump, int n) {
        for (int i = 0; i < n; i++) {
            dump.append(0).append(separator);
        }
    }

    public String dumpFlowBasedFeaturesEx() {
        StringBuilder dump = new StringBuilder();

        dump.append(flowId).append(separator);                                        //1
        dump.append(FormatUtils.ip(src)).append(separator);                        //2
        dump.append(getSrcPort()).append(separator);                                //3
        dump.append(FormatUtils.ip(dst)).append(separator);                        //4
        dump.append(getDstPort()).append(separator);                                //5
        dump.append(getProtocol()).append(separator);                                //6

        String starttime = convertMilliseconds2String(flowStartTime / 1000L, "yyyy-MM-dd HH:mm:ss");
        dump.append(starttime).append(separator);                                    //7

        long flowDuration = flowLastSeenTime - flowStartTime;
        dump.append(flowDuration).append(separator);                                //8

        dump.append(fwdPktStats.getN()).append(separator);                            //9
        dump.append(bwdPktStats.getN()).append(separator);                            //10
        dump.append(fwdPktStats.getSum()).append(separator);                        //11
        dump.append(bwdPktStats.getSum()).append(separator);                        //12

        if (fwdPktStats.getN() > 0L) {
            dump.append(fwdPktStats.getMax()).append(separator);                    //13
            dump.append(fwdPktStats.getMin()).append(separator);                    //14
            dump.append(fwdPktStats.getMean()).append(separator);                    //15
            dump.append(fwdPktStats.getStandardDeviation()).append(separator);        //16
        } else {
            addZeros(dump, 4);
        }

        if (bwdPktStats.getN() > 0L) {
            dump.append(bwdPktStats.getMax()).append(separator);                    //17
            dump.append(bwdPktStats.getMin()).append(separator);                    //18
            dump.append(bwdPktStats.getMean()).append(separator);                    //19
            dump.append(bwdPktStats.getStandardDeviation()).append(separator);        //20
        } else {
            addZeros(dump, 4);
        }

        if (this.forward.size() + this.backward.size() > 1) {
            dump.append(((double) (fwdBytes + bwdBytes)) / ((double) flowDuration / 1000000L)).append(separator);//21
            dump.append(((double) getPacketCount()) / ((double) flowDuration / 1000000L)).append(separator);//22
            dump.append(flowIAT.getMean()).append(separator);                            //23
            dump.append(flowIAT.getStandardDeviation()).append(separator);                //24
            dump.append(flowIAT.getMax()).append(separator);                            //25
            dump.append(flowIAT.getMin()).append(separator);                            //26
        } else {
            addZeros(dump, 6);
        }


        if (this.forward.size() > 1) {
            dump.append(forwardIAT.getSum()).append(separator);                        //27
            dump.append(forwardIAT.getMean()).append(separator);                    //28
            dump.append(forwardIAT.getStandardDeviation()).append(separator);        //29
            dump.append(forwardIAT.getMax()).append(separator);                        //30
            dump.append(forwardIAT.getMin()).append(separator);                        //31
        } else {
            addZeros(dump, 5);
        }

        if (this.backward.size() > 1) {
            dump.append(backwardIAT.getSum()).append(separator);                    //32
            dump.append(backwardIAT.getMean()).append(separator);                    //33
            dump.append(backwardIAT.getStandardDeviation()).append(separator);        //34
            dump.append(backwardIAT.getMax()).append(separator);                    //35
            dump.append(backwardIAT.getMin()).append(separator);                    //36
        } else {
            addZeros(dump, 5);
        }

        dump.append(flagCounts.get("PSH_FWD").value).append(separator);                                    //37
        dump.append(flagCounts.get("PSH_BWD").value).append(separator);                                    //38
        dump.append(flagCounts.get("UGR_FWD").value).append(separator);                                    //39
        dump.append(flagCounts.get("URG_BWD").value).append(separator);                                    //40

        dump.append(fwdHeaderBytes).append(separator);                                //41
        dump.append(bwdHeaderBytes).append(separator);                                //42
        dump.append(getfPktsPerSecond()).append(separator);                            //43
        dump.append(getbPktsPerSecond()).append(separator);                            //44


        if (this.forward.size() > 0 || this.backward.size() > 0) {
            dump.append(flowLengthStats.getMin()).append(separator);                //45
            dump.append(flowLengthStats.getMax()).append(separator);                //46
            dump.append(flowLengthStats.getMean()).append(separator);                //47
            dump.append(flowLengthStats.getStandardDeviation()).append(separator);    //48
            dump.append(flowLengthStats.getVariance()).append(separator);            //49
        } else {//seem to less one
            addZeros(dump, 5);
        }
		
		/*for(MutableInt v:flagCounts.values()) {
			dump.append(v).append(separator);
		}
		for(String key: flagCounts.keySet()){
			dump.append(flagCounts.get(key).value).append(separator);				//50,51,52,53,54,55,56,57
		} */
        dump.append(flagCounts.get("FIN").value).append(separator);                 //50
        dump.append(flagCounts.get("SYN").value).append(separator);                 //51
        dump.append(flagCounts.get("RST").value).append(separator);                  //52
        dump.append(flagCounts.get("PSH").value).append(separator);                  //53
        dump.append(flagCounts.get("ACK").value).append(separator);                  //54
        dump.append(flagCounts.get("URG").value).append(separator);                  //55
        dump.append(flagCounts.get("CWR").value).append(separator);                  //56
        dump.append(flagCounts.get("ECE").value).append(separator);                  //57

        dump.append(getDownUpRatio()).append(separator);                            //58
//        dump.append(getAvgPacketSize()).append(separator);                            //59
        dump.append(fAvgSegmentSize()).append(separator);                            //60
        dump.append(bAvgSegmentSize()).append(separator);                            //61
        //dump.append(fHeaderBytes).append(separator);								//62 dupicate with 41

        dump.append(fAvgBytesPerBulk()).append(separator);                            //63
        dump.append(fAvgPacketsPerBulk()).append(separator);                        //64
        dump.append(fAvgBulkRate()).append(separator);                                //65
        dump.append(bAvgBytesPerBulk()).append(separator);                            //66
        dump.append(bAvgPacketsPerBulk()).append(separator);                        //67
        dump.append(bAvgBulkRate()).append(separator);                                //68

        dump.append(getSflow_fpackets()).append(separator);                            //69
        dump.append(getSflow_fbytes()).append(separator);                            //70
        dump.append(getSflow_bpackets()).append(separator);                            //71
        dump.append(getSflow_bbytes()).append(separator);                            //72

        dump.append(fwdInitWinBytes).append(separator);                        //73
        dump.append(bwdInitWinBytes).append(separator);                        //74
        dump.append(fwdPacketsWithData).append(separator);                        //75
        dump.append(minFwdSegmentSize).append(separator);                        //76


        if (this.flowActive.getN() > 0) {
            dump.append(flowActive.getMean()).append(separator);                    //77
            dump.append(flowActive.getStandardDeviation()).append(separator);        //78
            dump.append(flowActive.getMax()).append(separator);                        //79
            dump.append(flowActive.getMin()).append(separator);                        //80
        } else {
            addZeros(dump, 4);
        }

        if (this.flowIdle.getN() > 0) {
            dump.append(flowIdle.getMean()).append(separator);                        //81
            dump.append(flowIdle.getStandardDeviation()).append(separator);            //82
            dump.append(flowIdle.getMax()).append(separator);                        //83
            dump.append(flowIdle.getMin()).append(separator);                        //84
        } else {
            addZeros(dump, 4);
        }

        dump.append(getLand()).append(separator); // land
        dump.append(getService()).append(separator); // service
        dump.append(wrongFragmentCount).append(separator); // wrong_fragment
        dump.append(getFlowState()).append(separator); // flow_state

        dump.append(getLabel());

        return dump.toString();
    }
}
