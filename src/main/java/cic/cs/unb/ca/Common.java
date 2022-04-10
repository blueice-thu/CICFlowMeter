package cic.cs.unb.ca;

public class Common {
    public static final String FILE_SEP = System.getProperty("file.separator");
    public static final String ROOT_PATH = System.getProperty("user.dir");
    public static final String LINE_SEP = System.lineSeparator();
    public static final String FLOW_SUFFIX = "_Flow.csv";
    public static final String FLOW_DATA_PATH = ROOT_PATH + FILE_SEP + "data" + FILE_SEP;
    public static final String FLOW_SAVE_PATH = FLOW_DATA_PATH + "daily" + FILE_SEP;
    public static final String PCAP_IDENTIFIER = "application/vnd.tcpdump.pcap";
}
