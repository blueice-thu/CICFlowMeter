package cic.cs.unb.ca.flow;

import cic.cs.unb.ca.Sys;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.LocalDate;


public class FlowMgr {

    public static final String FLOW_SUFFIX = "_Flow.csv";
    protected static final Logger logger = LoggerFactory.getLogger(FlowMgr.class);
    private static final FlowMgr Instance = new FlowMgr();

    @Getter private String flowSavePath;
    @Getter private String flowDataPath;

    private FlowMgr() {
        super();
    }

    public static FlowMgr getInstance() {
        return Instance;
    }

    public void init() {
        String rootPath = System.getProperty("user.dir");

        StringBuilder pathBuilder = new StringBuilder(rootPath);
        pathBuilder.append(Sys.FILE_SEP).append("data").append(Sys.FILE_SEP);
        flowDataPath = pathBuilder.toString();

        pathBuilder.append("daily").append(Sys.FILE_SEP);
        flowSavePath = pathBuilder.toString();
    }

    public void destroy() {
    }

    public String getAutoSaveFile() {
        String filename = LocalDate.now() + FLOW_SUFFIX;
        return flowSavePath + filename;
    }
}
