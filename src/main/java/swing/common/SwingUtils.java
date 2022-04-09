package swing.common;

import org.apache.tika.Tika;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.awt.*;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.LineNumberReader;

/**
 * Created by yzhang29 on 23/11/17.
 */
public class SwingUtils {
    protected static final Logger logger = LoggerFactory.getLogger(SwingUtils.class);
    private final static String PCAP = "application/vnd.tcpdump.pcap";

    public static void setBorderLayoutPane(Container container, Component comp, Object constraints) {

        if (container == null) {
            throw new IllegalArgumentException("BorderLayoutPane cannot be null!!");
        }

        BorderLayout layout = (BorderLayout) container.getLayout();
        Component oldComp = layout.getLayoutComponent(constraints);

        if (oldComp == null) {
            if (comp != null) {
                container.add(comp, constraints);
            }
            container.repaint();
            container.revalidate();
        } else {
            if (comp != oldComp) {
                container.remove(oldComp);
                if (comp != null) {
                    container.add(comp, constraints);
                }
                container.repaint();
                container.revalidate();
            }
        }
    }

    public static boolean isPcapFile(File file) {

        if (file == null) {
            return false;
        }

        try {

            String contentType;

            //Files.probeContentType returns null on Windows
            /*Path filePath = Paths.get(file.getPath());
            contentType = Files.probeContentType(filePath);*/

            contentType = new Tika().detect(file);

            return PCAP.equalsIgnoreCase(contentType);

        } catch (IOException e) {
            logger.debug(e.getMessage());
        }

        return false;
    }

    public static long countLines(String fileName) {
        File file = new File(fileName);
        int linenumber = 0;
        FileReader fr;
        LineNumberReader lnr = null;
        try {
            fr = new FileReader(file);
            lnr = new LineNumberReader(fr);

            while (lnr.readLine() != null) {
                linenumber++;
            }

        } catch (IOException e) {
            logger.debug(e.getMessage());
        } finally {

            if (lnr != null) {

                try {
                    lnr.close();
                } catch (IOException e) {
                    logger.debug(e.getMessage());
                }
            }
        }
        return linenumber;
    }
}
