package cic.cs.unb.ca.ui;

import cic.cs.unb.ca.jnetpcap.BasicFlow;
import cic.cs.unb.ca.jnetpcap.PcapIfWrapper;
import cic.cs.unb.ca.jnetpcap.feature.FlowFeature;
import cic.cs.unb.ca.worker.InsertCsvRow;
import cic.cs.unb.ca.worker.LoadPcapInterfaceWorker;
import cic.cs.unb.ca.worker.TrafficFlowWorker;
import org.apache.commons.lang3.StringUtils;
import org.jnetpcap.PcapIf;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import swing.common.InsertTableRow;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.io.File;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CancellationException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import static cic.cs.unb.ca.Common.*;

public class FlowRealtimePane extends JPanel {
    protected static final Logger logger = LoggerFactory.getLogger(FlowRealtimePane.class);


    private JTable flowTable;
    private DefaultTableModel defaultTableModel;
    private JList<PcapIfWrapper> list;
    private DefaultListModel<PcapIfWrapper> listModel;
    private JLabel lblStatus;
    private JLabel lblFlowCnt;

    private TrafficFlowWorker mWorker;

    private JButton btnLoad;
    private JToggleButton btnStart;
    private JToggleButton btnStop;
    private ButtonGroup btnGroup;

    private JButton btnSave = new JButton();
    private File lastSave;
    private JButton btnGraph = new JButton();
    private JFileChooser fileChooser;

    private ExecutorService csvWriterThread;


    public FlowRealtimePane() {
        init();

        setLayout(new BorderLayout(5, 5));
        setBorder(new EmptyBorder(10, 10, 10, 10));

        add(initCenterPane(), BorderLayout.CENTER);
    }

    private void init() {
        csvWriterThread = Executors.newSingleThreadExecutor();
    }

    public void destory() {
        csvWriterThread.shutdown();
    }

    private JPanel initCenterPane() {
        JPanel pane = new JPanel();
        pane.setLayout(new BorderLayout(0, 0));
        pane.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));

        JSplitPane splitPane = new JSplitPane(JSplitPane.VERTICAL_SPLIT, initFlowPane(), initNWifsPane());
        splitPane.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));
        splitPane.setOneTouchExpandable(true);
        splitPane.setResizeWeight(1.0);

        pane.add(splitPane, BorderLayout.CENTER);
        return pane;
    }

    private JPanel initFlowPane() {
        JPanel pane = new JPanel();
        pane.setLayout(new BorderLayout(0, 5));
        pane.setBorder(BorderFactory.createLineBorder(new Color(0x555555)));

        //pane.add(initTableBtnPane(), BorderLayout.NORTH);
        pane.add(initTablePane(), BorderLayout.CENTER);
        pane.add(initStatusPane(), BorderLayout.SOUTH);

        return pane;
    }

    private JPanel initTablePane() {
        JPanel pane = new JPanel();
        pane.setLayout(new BorderLayout(0, 0));
        pane.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));


        String[] arrayHeader = StringUtils.split(FlowFeature.getHeader(), ",");
        defaultTableModel = new DefaultTableModel(arrayHeader, 0);
        flowTable = new JTable(defaultTableModel);
        flowTable.setAutoResizeMode(JTable.AUTO_RESIZE_OFF);
        JScrollPane scrollPane = new JScrollPane(flowTable);
        scrollPane.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));


        pane.add(scrollPane, BorderLayout.CENTER);

        return pane;
    }

    private JPanel initStatusPane() {
        JPanel pane = new JPanel();
        pane.setLayout(new BoxLayout(pane, BoxLayout.X_AXIS));
        lblStatus = new JLabel("Get ready");
        lblStatus.setForeground(SystemColor.desktop);
        lblFlowCnt = new JLabel("0");

        pane.add(Box.createHorizontalStrut(5));
        pane.add(lblStatus);
        pane.add(Box.createHorizontalGlue());
        pane.add(lblFlowCnt);
        pane.add(Box.createHorizontalStrut(5));

        return pane;
    }

    private JPanel initNWifsPane() {
        JPanel pane = new JPanel(new BorderLayout(0, 0));
        pane.setBorder(BorderFactory.createLineBorder(new Color(0x555555)));
        pane.add(initNWifsButtonPane(), BorderLayout.WEST);
        pane.add(initNWifsListPane(), BorderLayout.CENTER);

        return pane;
    }

    private JPanel initNWifsButtonPane() {
        JPanel pane = new JPanel();
        pane.setBorder(BorderFactory.createEmptyBorder(10, 15, 10, 15));
        pane.setLayout(new BoxLayout(pane, BoxLayout.Y_AXIS));

        Dimension d = new Dimension(80, 48);

        btnLoad = new JButton("Load");
        btnLoad.setMinimumSize(d);
        btnLoad.setMaximumSize(d);
        btnLoad.addActionListener(actionEvent -> loadPcapIfs());

        btnStart = new JToggleButton("Start");
        btnStart.setMinimumSize(d);
        btnStart.setMaximumSize(d);
        btnStart.setEnabled(false);
        btnStart.addActionListener(actionEvent -> startTrafficFlow());

        btnStop = new JToggleButton("Stop");
        btnStop.setMinimumSize(d);
        btnStop.setMaximumSize(d);
        btnStop.setEnabled(false);
        btnStop.addActionListener(actionEvent -> stopTrafficFlow());

        btnGroup = new ButtonGroup();
        btnGroup.add(btnStart);
        btnGroup.add(btnStop);

        pane.add(Box.createVerticalGlue());
        pane.add(btnLoad);
        pane.add(Box.createVerticalGlue());
        pane.add(btnStart);
        pane.add(Box.createVerticalGlue());
        pane.add(btnStop);
        pane.add(Box.createVerticalGlue());

        return pane;
    }

    private JPanel initNWifsListPane() {
        JPanel pane = new JPanel();
        pane.setLayout(new BorderLayout(0, 0));
        pane.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));

        listModel = new DefaultListModel<>();
        listModel.addElement(new PcapIfWrapper("Click Load button to load network interfaces"));
        list = new JList<>(listModel);
        list.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        list.setSelectedIndex(0);
        JScrollPane scrollPane = new JScrollPane(list);
        scrollPane.setBorder(BorderFactory.createEmptyBorder(0, 0, 0, 0));

        pane.add(scrollPane, BorderLayout.CENTER);
        return pane;
    }

    private void loadPcapIfs() {
        LoadPcapInterfaceWorker task = new LoadPcapInterfaceWorker();
        task.addPropertyChangeListener(event -> {
            if ("state".equals(event.getPropertyName())) {
                LoadPcapInterfaceWorker task1 = (LoadPcapInterfaceWorker) event.getSource();
                switch (task1.getState()) {
                    case STARTED:
                        break;
                    case DONE:
                        try {
                            java.util.List<PcapIf> ifs = task1.get();
                            List<PcapIfWrapper> pcapiflist = PcapIfWrapper.fromPcapIf(ifs);

                            listModel.removeAllElements();
                            for (PcapIfWrapper pcapif : pcapiflist) {
                                listModel.addElement(pcapif);
                            }
                            btnStart.setEnabled(true);
                            btnGroup.clearSelection();

                            lblStatus.setText("pick one network interface to listening");
                            lblStatus.validate();

                        } catch (InterruptedException | ExecutionException e) {
                            logger.debug(e.getMessage());
                        }
                        break;
                }
            }
        });
        task.execute();
    }

    private void startTrafficFlow() {

        if (list.getSelectedValue() == null) {
            return;
        }
        String ifName = list.getSelectedValue().name();

        if (mWorker != null && !mWorker.isCancelled()) {
            return;
        }

        mWorker = new TrafficFlowWorker(ifName);
        mWorker.addPropertyChangeListener(event -> {
            TrafficFlowWorker task = (TrafficFlowWorker) event.getSource();
            if ("progress".equals(event.getPropertyName())) {
                lblStatus.setText((String) event.getNewValue());
                lblStatus.validate();
            } else if (TrafficFlowWorker.PROPERTY_FLOW.equalsIgnoreCase(event.getPropertyName())) {
                insertFlow((BasicFlow) event.getNewValue());
            } else if ("state".equals(event.getPropertyName())) {
                switch (task.getState()) {
                    case STARTED:
                        break;
                    case DONE:
                        try {
                            lblStatus.setText(task.get());
                            lblStatus.validate();
                        } catch (CancellationException e) {

                            lblStatus.setText("stop listening");
                            lblStatus.setForeground(SystemColor.GRAY);
                            lblStatus.validate();
                            logger.info("Pcap stop listening");

                        } catch (InterruptedException | ExecutionException e) {
                            logger.debug(e.getMessage());
                        }
                        break;
                }
            }
        });
        mWorker.execute();
        lblStatus.setForeground(SystemColor.desktop);
        btnLoad.setEnabled(false);
        btnStop.setEnabled(true);
    }

    private void stopTrafficFlow() {

        if (mWorker != null) {
            mWorker.cancel(true);
        }

        btnLoad.setEnabled(true);


        String path = FLOW_SAVE_PATH + LocalDate.now() + FLOW_SUFFIX;
        logger.info("path:{}", path);

        if (defaultTableModel.getRowCount() > 0 && new File(path).exists()) {
            String msg = "The flow has been saved to :" + LINE_SEP + path;

            UIManager.put("OptionPane.minimumSize", new Dimension(0, 0));
            JOptionPane.showMessageDialog(this.getParent(), msg);
        }
    }

    private void insertFlow(BasicFlow flow) {
        List<String> flowStringList = new ArrayList<>();
        List<String[]> flowDataList = new ArrayList<>();
        String flowDump = flow.dumpFlowBasedFeaturesEx();
        flowStringList.add(flowDump);
        flowDataList.add(StringUtils.split(flowDump, ","));

        //write flows to csv file
        String header = FlowFeature.getHeader();
        String filename = LocalDate.now() + FLOW_SUFFIX;
        csvWriterThread.execute(new InsertCsvRow(header, flowStringList, FLOW_SAVE_PATH, filename));

        //insert flows to JTable
        SwingUtilities.invokeLater(new InsertTableRow(defaultTableModel, flowDataList, lblFlowCnt));
        btnSave.setEnabled(true);
    }
}
