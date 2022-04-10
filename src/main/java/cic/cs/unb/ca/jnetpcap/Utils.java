package cic.cs.unb.ca.jnetpcap;

import org.apache.tika.Tika;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.LineNumberReader;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public class Utils {
    protected static final Logger logger = LoggerFactory.getLogger(Utils.class);
    private final static String PCAP = "application/vnd.tcpdump.pcap";

    private static boolean isPcapFile(String contentType) {

        return PCAP.equalsIgnoreCase(contentType);
    }

    public static boolean isPcapFile(File file) {

        if (file == null) {
            return false;
        }

        try {

            //Files.probeContentType returns null on Windows
            /*Path filePath = Paths.get(file.getPath());
            contentType = Files.probeContentType(filePath);*/

            return isPcapFile(new Tika().detect(file));

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

    public static String convertMilliseconds2String(long time, String format) {

        if (format == null) {
            format = "yyyy-MM-dd HH:mm:ss";
        }

        DateTimeFormatter formatter = DateTimeFormatter.ofPattern(format);
        LocalDateTime ldt = LocalDateTime.ofInstant(Instant.ofEpochMilli(time), ZoneId.systemDefault());
        return ldt.format(formatter);
    }

}
