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

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;

import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static org.junit.Assert.assertEquals;

public class RequestTest {
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    HFClient hfclient;
    InputStream mockstream;
    File someFileLocation = new File("");
    File someFileLocation2 = new File("");

    @Before
    public void setupClient() throws Exception {
        hfclient = HFClient.createNewInstance();
        mockstream = new ByteArrayInputStream(new byte[0]);

    }

    @Test
    public void testinstallProposalRequestStreamWithMeta() throws Exception {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Chaincode META-INF location may not be set with chaincode input stream set.");

        InstallProposalRequest installProposalRequest = hfclient.newInstallProposalRequest();

        installProposalRequest.setChaincodeInputStream(mockstream);
        installProposalRequest.setChaincodeMetaInfLocation(someFileLocation);

    }

    @Test
    public void testinstallProposalRequestStreamWithSourceLocation() throws Exception {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Error setting chaincode location. Chaincode input stream already set. Only one or the other maybe set.");

        InstallProposalRequest installProposalRequest = hfclient.newInstallProposalRequest();

        installProposalRequest.setChaincodeInputStream(mockstream);
        assertEquals(installProposalRequest.getChaincodeInputStream(), mockstream);
        installProposalRequest.setChaincodeSourceLocation(someFileLocation);

    }

    @Test
    public void testinstallProposalRequestWithLocationSetStream() throws Exception {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Error setting chaincode input stream. Chaincode source location already set. Only one or the other maybe set.");

        InstallProposalRequest installProposalRequest = hfclient.newInstallProposalRequest();

        installProposalRequest.setChaincodeSourceLocation(someFileLocation);
        installProposalRequest.setChaincodeInputStream(mockstream);

    }

    @Test
    public void testinstallProposalRequestWithMetaInfSetStream() throws Exception {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Error setting chaincode input stream. Chaincode META-INF location  already set. Only one or the other maybe set.");

        InstallProposalRequest installProposalRequest = hfclient.newInstallProposalRequest();

        installProposalRequest.setChaincodeMetaInfLocation(someFileLocation);
        installProposalRequest.setChaincodeInputStream(mockstream);

    }

    @Test
    public void testinstallProposalRequestWithMetaInfSetStreamNULL() throws Exception {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Chaincode META-INF location may not be null.");

        InstallProposalRequest installProposalRequest = hfclient.newInstallProposalRequest();

        installProposalRequest.setChaincodeMetaInfLocation(null);
    }

    @Test
    public void testinstallProposalRequestWithSourceNull() throws Exception {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Chaincode source location may not be null");

        InstallProposalRequest installProposalRequest = hfclient.newInstallProposalRequest();

        installProposalRequest.setChaincodeSourceLocation(null);
    }

    @Test
    public void testinstallProposalRequestWithInputStreamNULL() throws Exception {
        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Chaincode input stream may not be null.");

        InstallProposalRequest installProposalRequest = hfclient.newInstallProposalRequest();

        installProposalRequest.setChaincodeInputStream(null);
    }

    @Test
    public void testinstallProposalRequestLocationAndMeta() throws Exception {

        InstallProposalRequest installProposalRequest = hfclient.newInstallProposalRequest();

        installProposalRequest.setChaincodeSourceLocation(someFileLocation);
        installProposalRequest.setChaincodeMetaInfLocation(someFileLocation2);

        assertEquals(installProposalRequest.getChaincodeSourceLocation(), someFileLocation);
        assertEquals(installProposalRequest.getChaincodeMetaInfLocation(), someFileLocation2);

    }

}
