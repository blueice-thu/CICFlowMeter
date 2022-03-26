package cic.cs.unb.ca.flow.ui;

import cic.cs.unb.ca.weka.WekaXMeans;

import java.io.File;

public class FlowFileInfo {

    private final File filepath;
    private final WekaXMeans xMeans;

    public FlowFileInfo(File filepath, WekaXMeans xMeans) {
        this.filepath = filepath;
        this.xMeans = xMeans;
    }


    @Override
    public String toString() {
        return filepath.getName();
    }

    public File getFilepath() {
        return filepath;
    }

    public WekaXMeans getxMeans() {
        return xMeans;
    }
}
