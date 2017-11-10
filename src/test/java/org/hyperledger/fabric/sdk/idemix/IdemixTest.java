/*
 *
 *  Copyright IBM Corp. All Rights Reserved.
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

package org.hyperledger.fabric.sdk.idemix;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import org.apache.milagro.amcl.FP256BN.BIG;
import org.apache.milagro.amcl.RAND;
import org.junit.Test;
import static org.junit.Assert.assertTrue;


public class IdemixTest {

    @Test
    public void idemixTest() throws ExecutionException, InterruptedException {
        int numberOfThreadTasks = 10;
        // N tasks runned in pools of X threads.
        int threadPool = 25;
        ExecutorService serviceSingleTask =  Executors.newFixedThreadPool(threadPool);
        ExecutorService serviceMultiTask =  Executors.newFixedThreadPool(threadPool);

        // Select attribute names and generate a Idemix Setup
        String[] attributeNames = {"Attribute1", "Attribute2"};
        IdemixSetup setup = new IdemixSetup(attributeNames);

        // One single task running in parallel in a pool of threads.
        IdemixTask taskS = new IdemixTask(setup, 50);
        Future<Boolean> result = serviceSingleTask.submit(taskS);
        assertTrue(result.get());

        // i tasks running at the same time in parallel in different thread pools.
        List<Future<Boolean>> results = new ArrayList<>();
        for (int i = numberOfThreadTasks; i > 0; i--) {
            IdemixTask taskM = new IdemixTask(setup, 50);
            results.add(serviceMultiTask.submit(taskM));
        }
        for (Future<Boolean> f: results) {
            assertTrue(f.get());
        }
    }

    private class IdemixSetup {
        private String[] attributeNames;
        private IdemixIssuerKey key;
        private BIG sk;
        private BIG issuerNonce;
        private IdemixCredRequest idemixCredRequest;
        private IdemixCredential idemixCredential;
        private BIG[] attrs;

        private IdemixSetup(String[] attributeNames) {
            // Choose attribute names and create an issuer key pair
            // this.attributeNames = new String[]{"Attribute1", "Attribute2"};
            this.attributeNames = attributeNames;
            this.key = new IdemixIssuerKey(this.attributeNames);
            final RAND rng = IdemixUtils.getRand();
            // Choose a user secret key and request a credential
            this.sk = new BIG(IdemixUtils.randModOrder(rng));
            this.issuerNonce = new BIG(IdemixUtils.randModOrder(rng));
            this.idemixCredRequest = new IdemixCredRequest(this.sk, this.issuerNonce, this.key.getIpk()); //csr

            // Issue a credential
            this.attrs = new BIG[this.attributeNames.length];
            for (int i = 0; i < this.attributeNames.length; i++) {
                this.attrs[i] = new BIG(i);
            }
            this.idemixCredential = new IdemixCredential(this.key, this.idemixCredRequest, this.attrs); //certificate

            // Check all the generated data
            checkSetup();
        }

        @Test
        private void checkSetup() {
            // check that the issuer public key is valid
            assertTrue(this.key.getIpk().check());
            // Test serialization of issuer public key
            assertTrue(new IdemixIssuerPublicKey(this.key.getIpk().toProto()).check());
            // Test credential request
            assertTrue(this.idemixCredRequest.check(this.key.getIpk()));
            // Test serialization of cred request
            assertTrue(new IdemixCredRequest(this.idemixCredRequest.toProto()).check(key.getIpk()));
        }
    }

    private class IdemixTask implements Callable<Boolean> {
        private IdemixSetup setup;
        private int numberOfIterations;

        private IdemixTask(IdemixSetup idemixSetup, int numberOfIterations) {
            this.setup = idemixSetup;
            this.numberOfIterations = numberOfIterations;
        }

        private void test() {
            // user completes the idemixCredential and checks validity
            assertTrue(setup.idemixCredential.verify(setup.sk, setup.key.getIpk()));

            // Test serialization of IdemixidemixCredential
            assertTrue(new IdemixCredential(setup.idemixCredential.toProto()).verify(setup.sk, setup.key.getIpk()));

            // Create a new unlinkable pseudonym
            IdemixPseudonym pseudonym = new IdemixPseudonym(setup.sk, setup.key.getIpk()); //tcert

            // Generate new signature, disclosing no attributes
            boolean[] disclosure = {false, false};
            byte[] msg = {1, 2, 3, 4};
            IdemixSignature sig = new IdemixSignature(setup.idemixCredential, setup.sk, pseudonym, setup.key.getIpk(), disclosure, msg);
            // check that the signature is valid
            assertTrue(sig.verify(disclosure, setup.key.getIpk(), msg, setup.attrs));

            // Test serialization of IdemixSignature
            assertTrue(new IdemixSignature(sig.toProto()).verify(disclosure, setup.key.getIpk(), msg, setup.attrs));

            // Generate new signature, disclosing both attributes
            disclosure = new boolean[] {true, true};
            sig = new IdemixSignature(setup.idemixCredential, setup.sk, pseudonym, setup.key.getIpk(), disclosure, msg);
            // check that the signature is valid
            assertTrue(sig.verify(disclosure, setup.key.getIpk(), msg, setup.attrs));

            // Sign a message with respect to a pseudonym
            IdemixPseudonymSignature nymsig = new IdemixPseudonymSignature(setup.sk, pseudonym, setup.key.getIpk(), msg);
            // check that the pseudonym signature is valid
            assertTrue(nymsig.verify(pseudonym.getNym(), setup.key.getIpk(), msg));

            // Test serialization of IdemixPseudonymSignature
            assertTrue(new IdemixPseudonymSignature(nymsig.toProto()).verify(pseudonym.getNym(), setup.key.getIpk(), msg));
        }

        @Override
        public Boolean call() {
            for (int i = numberOfIterations; i > 0; --i) {
                test();
            }
            return true;
        }
    }
}

