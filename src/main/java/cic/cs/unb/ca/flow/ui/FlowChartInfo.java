package cic.cs.unb.ca.flow.ui;

public class FlowChartInfo {

    private final String name;

    private final ChartContainer cc;


    public FlowChartInfo(String name, ChartContainer cc) {
        this.name = name;
        this.cc = cc;
    }

    public String getName() {
        return name;
    }

    public ChartContainer getCc() {
        return cc;
    }

    @Override
    public String toString() {
        return name;
    }
}
