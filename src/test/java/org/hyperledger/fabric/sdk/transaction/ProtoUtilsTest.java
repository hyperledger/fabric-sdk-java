/*
 *
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.hyperledger.fabric.sdk.transaction;

import java.util.Calendar;
import java.util.Date;

import com.google.protobuf.Timestamp;
import org.junit.Assert;
import org.junit.Test;

import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.getCurrentFabricTimestamp;
import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.getDateFromTimestamp;
import static org.hyperledger.fabric.sdk.transaction.ProtoUtils.getTimestampFromDate;

public class ProtoUtilsTest {

    @Test
    public void timeStampDrill() throws Exception {

        final long millis = System.currentTimeMillis();

        //Test values over 2seconds
        for (long start = millis; start < millis + 2010; ++start) {
            Timestamp ts = Timestamp.newBuilder().setSeconds(start / 1000)
                    .setNanos((int) ((start % 1000) * 1000000)).build();

            Date dateFromTimestamp = getDateFromTimestamp(ts);
            //    System.out.println(dateFromTimestamp);
            Date expectedDate = new Date(start);
            //Test various formats to make sure...
            Assert.assertEquals(expectedDate, dateFromTimestamp);
            Assert.assertEquals(expectedDate.getTime(), dateFromTimestamp.getTime());
            Assert.assertEquals(expectedDate.toString(), dateFromTimestamp.toString());
            //Now reverse it
            Timestamp timestampFromDate = getTimestampFromDate(expectedDate);
            Assert.assertEquals(ts, timestampFromDate);
            Assert.assertEquals(ts.getNanos(), timestampFromDate.getNanos());
            Assert.assertEquals(ts.getSeconds(), timestampFromDate.getSeconds());
            Assert.assertEquals(ts.toString(), timestampFromDate.toString());

        }

    }

    @Test
    public void timeStampCurrent() throws Exception {
        final int skew = 200;  // need some skew here as we are not getting the times at same instance.

        Calendar before = Calendar.getInstance(); // current time.

        final Date currentDateTimestamp = getDateFromTimestamp(getCurrentFabricTimestamp());
        Calendar after = (Calendar) before.clone(); // another copy.

        before.add(Calendar.MILLISECOND, -skew);
        after.add(Calendar.MILLISECOND, skew);
        Assert.assertTrue(before.getTime().before(currentDateTimestamp));
        Assert.assertTrue(after.getTime().after(currentDateTimestamp));
    }

}
