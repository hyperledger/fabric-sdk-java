/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk;

import java.io.File;
import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedList;

import org.hyperledger.fabric.sdk.events.EventHub;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

/**
 * Test end to end scenario
 */
@Ignore //Really not needed convered by End2endIt
public class ChainTestIT {

    static final String CHAIN_NAME = "foo";

    final static Collection<String> PEER_LOCATIONS = Arrays.asList("grpc://localhost:7051");


    final static Collection<String> ORDERER_LOCATIONS = Arrays.asList("grpc://localhost:7050"); //Vagrant maps to this

    final static Collection<String> EVENTHUB_LOCATIONS = Arrays.asList("grpc://localhost:7053"); //Vagrant maps to this

    final static String FABRIC_CA_SERVICES_LOCATION = "http://localhost:7054";

    private TestConfigHelper configHelper = new TestConfigHelper();

    @Before
    public void checkConfig() throws NoSuchFieldException, SecurityException, IllegalArgumentException, IllegalAccessException {
        configHelper.clearConfig();
        configHelper.customizeConfig();
    }

    @After
    public void clearConfig() {
        try {
            configHelper.clearConfig();
        } catch (Exception e) {
            e.printStackTrace();
            Assert.fail(e.getMessage());
        }
    }

    @Test
    public void setup() {

        try {

            HFClient client = HFClient.createNewInstance();

            ////////////////////////////
            // Setup client

            File fileStore = new File(System.getProperty("user.home") + "/test.properties");
            if (fileStore.exists()) {
                fileStore.delete();
            }
            client.setKeyValStore(new FileKeyValStore(fileStore));
            client.setMemberServices(new MemberServicesFabricCAImpl(FABRIC_CA_SERVICES_LOCATION, null));
            User user = client.enroll("admin", "adminpw");
            client.setUserContext(user);


            ////////////////////////////
            //Construct the chain
            //

            Collection<Orderer> orderers = new LinkedList<>();

            for (String orderloc : ORDERER_LOCATIONS) {
                orderers.add(client.newOrderer(orderloc));

            }

            //Just pick the first order in the list to create the chain.

            Orderer anOrderer = orderers.iterator().next();
            orderers.remove(anOrderer);

            ChainConfiguration chainConfiguration = new ChainConfiguration(new File("src/test/fixture/foo.configtx"));

            Chain newChain = client.newChain(CHAIN_NAME, anOrderer, chainConfiguration);

            for (String peerloc : PEER_LOCATIONS) {
                Peer peer = client.newPeer(peerloc);
                peer.setName("peer1");
                newChain.joinPeer(peer);

            }

            for (String eventHub : EVENTHUB_LOCATIONS) {
                EventHub orderer = client.newEventHub(eventHub);
                newChain.addEventHub(orderer);
            }

            for (Orderer orderer : orderers){
                newChain.addOrderer(orderer);
            }

        } catch (Exception e) {

            e.printStackTrace();

            Assert.fail("Unexpected Exception :" + e.getMessage());


        }

    }

    static void out(String format, Object... args) {

        System.err.flush();
        System.out.flush();

        System.out.println(String.format(format, args));
        System.err.flush();
        System.out.flush();

    }

}
