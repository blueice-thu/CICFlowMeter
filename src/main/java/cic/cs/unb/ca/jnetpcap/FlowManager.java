package cic.cs.unb.ca.jnetpcap;

public class FlowManager {
    private static FlowManager INSTANCE = null;

    private FlowManager() {}
    public synchronized static FlowManager getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new FlowManager();
        }
        return INSTANCE;
    }


}
