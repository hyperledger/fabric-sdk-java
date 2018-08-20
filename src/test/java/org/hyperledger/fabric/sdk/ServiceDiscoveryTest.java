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

package org.hyperledger.fabric.sdk;

import java.util.Collection;
import java.util.LinkedList;
import java.util.List;

import org.hyperledger.fabric.sdk.testutils.TestUtils;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.hyperledger.fabric.sdk.ServiceDiscovery.ENDORSEMENT_SELECTION_LEAST_REQUIRED_BLOCKHEIGHT;
import static org.hyperledger.fabric.sdk.ServiceDiscovery.EndorsementSelector;
import static org.hyperledger.fabric.sdk.ServiceDiscovery.SDChaindcode;
import static org.hyperledger.fabric.sdk.ServiceDiscovery.SDEndorser;
import static org.hyperledger.fabric.sdk.ServiceDiscovery.SDEndorserState;
import static org.hyperledger.fabric.sdk.ServiceDiscovery.SDLayout;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class ServiceDiscoveryTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void simpleOneEach() throws Exception {

        EndorsementSelector es = ENDORSEMENT_SELECTION_LEAST_REQUIRED_BLOCKHEIGHT;

        List<SDLayout> lol = new LinkedList<>();
        SDLayout sdLayout = new SDLayout();
        List<SDEndorser> sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org1", "localhost:80", 20));
        sdl.add(new MockSDEndorser("org1", "localhost:81", 20));
        sdLayout.addGroup("G1", 1, sdl);
        sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org2", "otherhost:90", 20));
        sdl.add(new MockSDEndorser("org2", "otherhost:91", 20));
        sdLayout.addGroup("G2", 1, sdl);
        lol.add(sdLayout);
        SDChaindcode cc = new SDChaindcode("fakecc", lol);
        SDEndorserState sdEndorserState = es.endorserSelector(cc);
        Collection<SDEndorser> sdEndorsers = sdEndorserState.getSdEndorsers();
        assertEquals(2, sdEndorsers.size());
        assertTrue(sdLayout == sdEndorserState.getPickedLayout());

        assertEquals(filterByEndpoint(sdEndorsers, "localhost").size(), 1);
        assertEquals(filterByEndpoint(sdEndorsers, "otherhost").size(), 1);

    }

    @Test
    public void simpleOneTwoEach() throws Exception {

        EndorsementSelector es = ENDORSEMENT_SELECTION_LEAST_REQUIRED_BLOCKHEIGHT;

        List<SDLayout> lol = new LinkedList<>();
        SDLayout sdLayout = new SDLayout();
        List<SDEndorser> sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org1", "localhost:80", 20));
        sdl.add(new MockSDEndorser("org1", "localhost:81", 20));
        sdLayout.addGroup("G1", 1, sdl);
        sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org2", "otherhost:90", 20));
        sdl.add(new MockSDEndorser("org2", "otherhost:91", 20));
        sdLayout.addGroup("G2", 2, sdl);
        lol.add(sdLayout);
        SDChaindcode cc = new SDChaindcode("fakecc", lol);
        SDEndorserState sdEndorserState = es.endorserSelector(cc);
        Collection<SDEndorser> sdEndorsers = sdEndorserState.getSdEndorsers();
        assertEquals(3, sdEndorsers.size());
        assertSame(sdLayout, sdEndorserState.getPickedLayout());

        assertEquals(filterByEndpoint(sdEndorsers, "localhost").size(), 1);
        assertEquals(filterByEndpoint(sdEndorsers, "otherhost").size(), 2);

    }

    @Test
    public void simpleTwoTwoEach() throws Exception {

        EndorsementSelector es = ENDORSEMENT_SELECTION_LEAST_REQUIRED_BLOCKHEIGHT;

        List<SDLayout> lol = new LinkedList<>();
        SDLayout sdLayout = new SDLayout();
        List<SDEndorser> sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org1", "localhost:80", 20));
        sdl.add(new MockSDEndorser("org1", "localhost:81", 20));
        sdLayout.addGroup("G1", 2, sdl);
        sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org2", "otherhost:90", 20));
        sdl.add(new MockSDEndorser("org2", "otherhost:91", 20));
        sdLayout.addGroup("G2", 2, sdl);
        lol.add(sdLayout);
        SDChaindcode cc = new SDChaindcode("fakecc", lol);
        SDEndorserState sdEndorserState = es.endorserSelector(cc);
        Collection<SDEndorser> sdEndorsers = sdEndorserState.getSdEndorsers();
        assertEquals(4, sdEndorsers.size());
        assertSame(sdLayout, sdEndorserState.getPickedLayout());

        assertEquals(filterByEndpoint(sdEndorsers, "localhost").size(), 2);
        assertEquals(filterByEndpoint(sdEndorsers, "otherhost").size(), 2);

    }

    @Test
    public void simpleTwoTwoEachExtras() throws Exception {

        EndorsementSelector es = ENDORSEMENT_SELECTION_LEAST_REQUIRED_BLOCKHEIGHT;

        List<SDLayout> lol = new LinkedList<>();
        SDLayout sdLayout = new SDLayout();
        List<SDEndorser> sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org1", "localhost:80", 20));
        sdl.add(new MockSDEndorser("org1", "localhost:81", 20));
        sdl.add(new MockSDEndorser("org1", "localhost:82", 20));
        sdLayout.addGroup("G1", 2, sdl);
        sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org2", "otherhost:93", 20));
        sdl.add(new MockSDEndorser("org2", "otherhost:90", 20));
        sdl.add(new MockSDEndorser("org2", "otherhost:91", 20));

        sdLayout.addGroup("G2", 2, sdl);
        lol.add(sdLayout);
        SDChaindcode cc = new SDChaindcode("fakecc", lol);
        SDEndorserState sdEndorserState = es.endorserSelector(cc);
        Collection<SDEndorser> sdEndorsers = sdEndorserState.getSdEndorsers();
        assertEquals(4, sdEndorsers.size());
        assertSame(sdLayout, sdEndorserState.getPickedLayout());

        assertEquals(filterByEndpoint(sdEndorsers, "localhost").size(), 2);
        assertEquals(filterByEndpoint(sdEndorsers, "otherhost").size(), 2);

    }

    @Test
    public void simpleTwoTwoEachExtrasCommon() throws Exception {

        EndorsementSelector es = ENDORSEMENT_SELECTION_LEAST_REQUIRED_BLOCKHEIGHT;

        List<SDLayout> lol = new LinkedList<>();
        SDLayout sdLayout = new SDLayout();
        List<SDEndorser> sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org1", "localhost:80", 20));
        sdl.add(new MockSDEndorser("org1", "localhost:81", 20));
        sdl.add(new MockSDEndorser("org1", "commonHost:82", 20));
        sdLayout.addGroup("G1", 2, sdl);
        sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org2", "otherhost:93", 20));
        sdl.add(new MockSDEndorser("org2", "otherhost:90", 20));
        sdl.add(new MockSDEndorser("org1", "commonHost:82", 20)); // << the same

        sdLayout.addGroup("G2", 2, sdl);
        lol.add(sdLayout);
        SDChaindcode cc = new SDChaindcode("fakecc", lol);
        SDEndorserState sdEndorserState = es.endorserSelector(cc);
        Collection<SDEndorser> sdEndorsers = sdEndorserState.getSdEndorsers();
        assertEquals(3, sdEndorsers.size());
        assertSame(sdLayout, sdEndorserState.getPickedLayout());

        assertEquals(filterByEndpoint(sdEndorsers, "localhost").size(), 1);
        assertEquals(filterByEndpoint(sdEndorsers, "otherhost").size(), 1);
        assertEquals(filterByEndpoint(sdEndorsers, "commonHost").size(), 1);

    }

    @Test
    public void twoLayoutTwoTwoEachExtrasCommon() throws Exception {

        EndorsementSelector es = ENDORSEMENT_SELECTION_LEAST_REQUIRED_BLOCKHEIGHT;

        List<SDLayout> lol = new LinkedList<>();
        SDLayout sdLayout = new SDLayout();
        List<SDEndorser> sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org1", "localhost:80", 20));
        sdl.add(new MockSDEndorser("org1", "localhost:81", 20));
        sdl.add(new MockSDEndorser("org1", "localhost:83", 20));
        sdLayout.addGroup("G1", 3, sdl);  // << 3 needed
        sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org2", "otherhost:93", 20));
        sdl.add(new MockSDEndorser("org2", "otherhost:90", 20));
        sdl.add(new MockSDEndorser("org1", "commonHost:82", 20));

        sdLayout.addGroup("G2", 2, sdl);
        lol.add(sdLayout);

        sdLayout = new SDLayout(); // another layout the above needs 3
        sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org1", "l2localhost:80", 20));
        sdl.add(new MockSDEndorser("org1", "l2localhost:81", 20));
        sdl.add(new MockSDEndorser("org1", "l2commonHost:82", 20));
        sdLayout.addGroup("G1", 2, sdl);
        sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org2", "l2otherhost:93", 20));
        sdl.add(new MockSDEndorser("org2", "l2otherhost:90", 20));
        sdl.add(new MockSDEndorser("org1", "l2commonHost:82", 20));

        sdLayout.addGroup("G2", 2, sdl);
        lol.add(sdLayout);

        SDChaindcode cc = new SDChaindcode("fakecc", lol);
        SDEndorserState sdEndorserState = es.endorserSelector(cc);
        Collection<SDEndorser> sdEndorsers = sdEndorserState.getSdEndorsers();
        assertEquals(3, sdEndorsers.size());
        assertSame(sdLayout, sdEndorserState.getPickedLayout());

        assertEquals(filterByEndpoint(sdEndorsers, "l2localhost").size(), 1);
        assertEquals(filterByEndpoint(sdEndorsers, "l2otherhost").size(), 1);
        assertEquals(filterByEndpoint(sdEndorsers, "l2commonHost").size(), 1);

    }

    @Test
    public void simpleOneEachRandom() throws Exception {

        EndorsementSelector es = EndorsementSelector.ENDORSEMENT_SELECTION_RANDOM;

        List<SDLayout> lol = new LinkedList<>();
        SDLayout sdLayout = new SDLayout();
        List<SDEndorser> sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org1", "localhost:80", 20));
        sdl.add(new MockSDEndorser("org1", "localhost:81", 20));
        sdLayout.addGroup("G1", 1, sdl);
        sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org2", "otherhost:90", 20));
        sdl.add(new MockSDEndorser("org2", "otherhost:91", 20));
        sdLayout.addGroup("G2", 1, sdl);
        lol.add(sdLayout);
        SDChaindcode cc = new SDChaindcode("fakecc", lol);
        SDEndorserState sdEndorserState = es.endorserSelector(cc);
        for (int i = 64; i > 0; --i) {
            Collection<SDEndorser> sdEndorsers = sdEndorserState.getSdEndorsers();
            assertEquals(2, sdEndorsers.size());
            assertSame(sdLayout, sdEndorserState.getPickedLayout());

            assertEquals(filterByEndpoint(sdEndorsers, "localhost").size(), 1);
            assertEquals(filterByEndpoint(sdEndorsers, "otherhost").size(), 1);
        }

    }

    @Test
    public void simpleOneTwoEachRandom() throws Exception {

        EndorsementSelector es = EndorsementSelector.ENDORSEMENT_SELECTION_RANDOM;

        List<SDLayout> lol = new LinkedList<>();
        SDLayout sdLayout = new SDLayout();
        List<SDEndorser> sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org1", "localhost:80", 20));
        sdl.add(new MockSDEndorser("org1", "localhost:81", 20));
        sdLayout.addGroup("G1", 1, sdl);
        sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org2", "otherhost:90", 20));
        sdl.add(new MockSDEndorser("org2", "otherhost:91", 20));
        sdLayout.addGroup("G2", 2, sdl);
        lol.add(sdLayout);
        SDChaindcode cc = new SDChaindcode("fakecc", lol);
        for (int i = 64; i > 0; --i) {
            SDEndorserState sdEndorserState = es.endorserSelector(cc);
            Collection<SDEndorser> sdEndorsers = sdEndorserState.getSdEndorsers();
            assertEquals(3, sdEndorsers.size());
            assertSame(sdLayout, sdEndorserState.getPickedLayout());

            assertEquals(filterByEndpoint(sdEndorsers, "localhost").size(), 1);
            assertEquals(filterByEndpoint(sdEndorsers, "otherhost").size(), 2);
        }

    }

    @Test
    public void twoLayoutTwoTwoEachExtrasCommonRandom() throws Exception {

        EndorsementSelector es = EndorsementSelector.ENDORSEMENT_SELECTION_RANDOM;

        List<SDLayout> lol = new LinkedList<>();
        SDLayout sdLayout = new SDLayout();
        List<SDEndorser> sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org1", "localhost:80", 20));
        sdl.add(new MockSDEndorser("org1", "localhost:81", 20));
        sdl.add(new MockSDEndorser("org1", "localhost:83", 20));
        sdLayout.addGroup("G1", 3, sdl);  // << 3 needed
        sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org2", "otherhost:93", 20));
        sdl.add(new MockSDEndorser("org2", "otherhost:90", 20));
        sdl.add(new MockSDEndorser("org2", "otherhost:82", 20));

        sdLayout.addGroup("G2", 2, sdl);
        lol.add(sdLayout);

        sdLayout = new SDLayout(); // another layout the above needs 3
        sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org1", "l2localhost:80", 20));
        sdl.add(new MockSDEndorser("org1", "l2localhost:81", 20));
        sdl.add(new MockSDEndorser("org1", "l2localhost:82", 20));
        sdLayout.addGroup("G1", 1, sdl);
        sdl = new LinkedList<>();
        sdl.add(new MockSDEndorser("org2", "l2otherhost:93", 20));
        sdl.add(new MockSDEndorser("org2", "l2otherhost:90", 20));
        sdl.add(new MockSDEndorser("org1", "l2otherhost:82", 20));

        sdLayout.addGroup("G2", 2, sdl);
        lol.add(sdLayout);

        SDChaindcode cc = new SDChaindcode("fakecc", lol);
        for (int i = 64; i > 0; --i) {
            SDEndorserState sdEndorserState = es.endorserSelector(cc);
            Collection<SDEndorser> sdEndorsers = sdEndorserState.getSdEndorsers();

            assertTrue((filterByEndpoint(sdEndorsers, "localhost").size() == 3 &&
                    filterByEndpoint(sdEndorsers, "otherhost").size() == 2) || (
                    filterByEndpoint(sdEndorsers, "l2localhost").size() == 1 &&
                            filterByEndpoint(sdEndorsers, "l2otherhost").size() == 2

            ));
        }

    }

    private static class MockSDEndorser extends SDEndorser {
        private MockSDEndorser(String mspid, String endpoint, long ledgerHeight) {
            super();
            TestUtils.setField(this, "endPoint", endpoint);
            TestUtils.setField(this, "mspid", mspid);
            TestUtils.setField(this, "ledgerHeight", ledgerHeight);
        }

    }

    private static List<SDEndorser> filterByEndpoint(Collection<SDEndorser> sdEndorsers, final String needle) {
        List<SDEndorser> ret = new LinkedList<>();
        sdEndorsers.forEach(sdEndorser -> {
            if (sdEndorser.getEndpoint().contains(needle)) {
                ret.add(sdEndorser);
            }
        });

        return ret;
    }

}
