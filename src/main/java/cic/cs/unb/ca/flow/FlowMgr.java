package cic.cs.unb.ca.flow;

import cic.cs.unb.ca.Sys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDate;


public class FlowMgr {

    public static final String FLOW_SUFFIX = "_Flow.csv";
    protected static final Logger logger = LoggerFactory.getLogger(FlowMgr.class);
    private static final FlowMgr Instance = new FlowMgr();

    private String mFlowSavePath;
    private String mDataPath;

    private FlowMgr() {
        super();
    }

    public static FlowMgr getInstance() {
        return Instance;
    }

    public void init() {

        String rootPath = System.getProperty("user.dir");
        StringBuilder sb = new StringBuilder(rootPath);
        sb.append(Sys.FILE_SEP).append("data").append(Sys.FILE_SEP);

        mDataPath = sb.toString();

        sb.append("daily").append(Sys.FILE_SEP);
        mFlowSavePath = sb.toString();

    }

    public void destroy() {
    }

    public String getSavePath() {
        return mFlowSavePath;
    }

    public String getmDataPath() {
        return mDataPath;
    }

    public String getAutoSaveFile() {
        String filename = LocalDate.now() + FLOW_SUFFIX;
        return mFlowSavePath + filename;
    }
}
