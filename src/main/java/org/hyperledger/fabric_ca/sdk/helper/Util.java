package org.hyperledger.fabric_ca.sdk.helper;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;

public class Util {

    /**
     * Converts Date type to String based on RFC3339 formatting
     *
     * @param date
     * @return String
     */
    public static String dateToString(Date date) {
        final TimeZone utc = TimeZone.getTimeZone("UTC");

        SimpleDateFormat tformat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
        tformat.setTimeZone(utc);
        return tformat.format(date);
    }

    /**
     * Private constructor to prevent instantiation.
     */
    private Util() {
    }
}
