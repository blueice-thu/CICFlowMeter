package cic.cs.unb.ca.ui;

import swing.common.SwingUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;

public class MainFrame extends JFrame {

    private static final long serialVersionUID = 7419600803861028585L;

    private final FlowOfflinePane offLinePane;
    private final FlowRealtimePane monitorPane;

    public MainFrame() throws HeadlessException {
        super("CICFlowMeter");

        getContentPane().setLayout(new BorderLayout());
        getContentPane().getInsets().set(5, 5, 5, 5);
        setIconImage(Toolkit.getDefaultToolkit().getImage(getClass().getClassLoader().getResource("CIC_Logo.png")));
        setMinimumSize(new Dimension(700, 500));
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setLocationRelativeTo(null);

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent windowEvent) {
                super.windowClosing(windowEvent);
                dispose();
                System.gc();
            }
        });

        initMenu();

        offLinePane = new FlowOfflinePane();
        monitorPane = new FlowRealtimePane();
        getContentPane().add(monitorPane, BorderLayout.CENTER);

        setVisible(true);
    }

    private void initMenu() {
        JMenuBar menuBar = new JMenuBar();
        setJMenuBar(menuBar);

        JMenu mnFile = new JMenu("File");
        menuBar.add(mnFile);

        JMenuItem itemExit = new JMenuItem("Exit");
        itemExit.addActionListener(arg0 -> {
            System.exit(EXIT_ON_CLOSE);
        });
        mnFile.add(itemExit);

        JMenu mnNetwork = new JMenu("NetWork");
        menuBar.add(mnNetwork);

        JMenuItem itemOffline = new JMenuItem("Offline");
        itemOffline.addActionListener(e -> SwingUtils.setBorderLayoutPane(getContentPane(), offLinePane, BorderLayout.CENTER));
        mnNetwork.add(itemOffline);

        JMenuItem itemRealtime = new JMenuItem("Realtime");
        itemRealtime.addActionListener(e -> SwingUtils.setBorderLayoutPane(getContentPane(), monitorPane, BorderLayout.CENTER));
        mnNetwork.add(itemRealtime);

    }

    @Override
    protected void finalize() throws Throwable {
        super.finalize();
    }
}
