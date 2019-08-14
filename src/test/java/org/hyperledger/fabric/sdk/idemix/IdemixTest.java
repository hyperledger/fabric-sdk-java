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
import org.apache.milagro.amcl.FP256BN.ECP;
import org.apache.milagro.amcl.RAND;
import org.hyperledger.fabric.protos.idemix.Idemix;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.testutils.TestConfig;
import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class IdemixTest {
    // Number of tasks to run
    static final int TASKS = 10;
    // How many taks we run at the same time
    static final int THREAD_POOL = 25;
    // How many iterations per task we do
    static final int ITERATIONS = 10;

    @Test
    public void idemixTest() throws ExecutionException, InterruptedException {
        if (!TestConfig.getConfig().getRunIdemixMTTest()) {
            return;
        }
        ExecutorService serviceSingleTask = Executors.newFixedThreadPool(THREAD_POOL);
        ExecutorService serviceMultiTask = Executors.newFixedThreadPool(THREAD_POOL);

        // Select attribute names and generate a Idemix Setup
        String[] attributeNames = {"Attr1", "Attr2", "Attr3", "Attr4", "Attr5"};
        IdemixSetup setup = new IdemixSetup(attributeNames);

        // One single task
        IdemixTask taskS = new IdemixTask(setup, RevocationAlgorithm.ALG_NO_REVOCATION);
        Future<Boolean> result = serviceSingleTask.submit(taskS);
        assertTrue(result.get());

        taskS = new IdemixTask(setup, RevocationAlgorithm.ALG_PLAIN_SIGNATURE);
        result = serviceSingleTask.submit(taskS);
        assertTrue(result.get());

        // i tasks running at the same time in parallel in different thread pools.
        List<Future<Boolean>> results = new ArrayList<>();
        for (int i = TASKS; i > 0; i--) {
            IdemixTask taskM = new IdemixTask(setup, RevocationAlgorithm.ALG_NO_REVOCATION);
            results.add(serviceMultiTask.submit(taskM));

            taskM = new IdemixTask(setup, RevocationAlgorithm.ALG_PLAIN_SIGNATURE);
            results.add(serviceMultiTask.submit(taskM));
        }
        for (Future<Boolean> f : results) {
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
        private WeakBB.KeyPair wbbKeyPair;
        private RevocationAuthority ra;
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

            this.wbbKeyPair = WeakBB.weakBBKeyGen();

            // Instantiate Revocation Authority
            this.ra = new RevocationAuthority();

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
        private int iterations;
        private RevocationAlgorithm revocationAlgorithm;

        private IdemixTask(IdemixSetup idemixSetup, RevocationAlgorithm revocationAlgorithm) {
            this.setup = idemixSetup;
            this.iterations = ITERATIONS;
            this.revocationAlgorithm = revocationAlgorithm;
        }

        private void test() throws CryptoException {
            final RAND rng = IdemixUtils.getRand();
            // WeakBB test
            // Random message to sign
            BIG wbbMessage = IdemixUtils.randModOrder(rng);
            // Sign the message with keypair secret key
            ECP wbbSignature = WeakBB.weakBBSign(setup.wbbKeyPair.getSk(), wbbMessage);
            // Check the signature with valid PK and valid message
            assertTrue(WeakBB.weakBBVerify(setup.wbbKeyPair.getPk(), wbbSignature, wbbMessage));
            // Try to check a random message
            assertFalse(WeakBB.weakBBVerify(setup.wbbKeyPair.getPk(), wbbSignature, IdemixUtils.randModOrder(rng)));

            // user completes the idemixCredential and checks validity
            assertTrue(setup.idemixCredential.verify(setup.sk, setup.key.getIpk()));

            // Test serialization of IdemixidemixCredential
            assertTrue(new IdemixCredential(setup.idemixCredential.toProto()).verify(setup.sk, setup.key.getIpk()));

            // Create CRI
            int epoch = 0;
            BIG[] rhIndex = {new BIG(0)}; // Recall that the revocationHandler for this.idemixCredential is 0
            Idemix.CredentialRevocationInformation cri = setup.ra.createCRI(rhIndex, epoch, revocationAlgorithm);

            // Create a new unlinkable pseudonym
            IdemixPseudonym pseudonym = new IdemixPseudonym(setup.sk, setup.key.getIpk()); //tcert

            // Test signing no disclosure
            boolean[] disclosure = {false, false, false, false, false};
            byte[] msg = {1, 2, 3, 4, 5};
            IdemixSignature signature = new IdemixSignature(setup.idemixCredential, setup.sk, pseudonym, setup.key.getIpk(), disclosure, msg, 0, cri);
            assertNotNull(signature);

            // Test bad disclosure: Disclosure > number of attributes || Disclosure < number of attributes
            boolean[] badDisclosure = {false, true};
            boolean[] badDisclosure2 = {true, true, true, true, true, true, true};
            try {
                new IdemixSignature(setup.idemixCredential, setup.sk, pseudonym, setup.key.getIpk(), badDisclosure, msg, 0, cri);
                new IdemixSignature(setup.idemixCredential, setup.sk, pseudonym, setup.key.getIpk(), badDisclosure2, msg, 0, cri);
                fail("Expected an IllegalArgumentException");
            } catch (IllegalArgumentException e) { /* Do nothing, the expected behaviour is to catch this exception.*/ }

            // check that the signature is valid
            assertTrue(signature.verify(disclosure, setup.key.getIpk(), msg, setup.attrs, 0, setup.ra.getPk(), epoch));

            // check that the signature is not valid with the respect to another epoch
            assertFalse(signature.verify(disclosure, setup.key.getIpk(), msg, setup.attrs, 0, setup.ra.getPk(), epoch + 1));

            // Test serialization of IdemixSignature
            assertTrue(new IdemixSignature(signature.toProto()).verify(disclosure, setup.key.getIpk(), msg, setup.attrs, 0, setup.ra.getPk(), epoch));

            // Test signing selective disclosure
            boolean[] disclosure2 = {false, true, true, true, false};
            signature = new IdemixSignature(setup.idemixCredential, setup.sk, pseudonym, setup.key.getIpk(), disclosure2, msg, 0, cri);
            assertNotNull(signature);

            // check that the signature is valid
            assertTrue(signature.verify(disclosure2, setup.key.getIpk(), msg, setup.attrs, 0, setup.ra.getPk(), epoch));

            // check that the signature is not valid with the respect to another epoch
            assertFalse(signature.verify(disclosure2, setup.key.getIpk(), msg, setup.attrs, 0, setup.ra.getPk(), epoch + 1));

            // Test signature verification with different disclosure
            assertFalse(signature.verify(disclosure, setup.key.getIpk(), msg, setup.attrs, 0, setup.ra.getPk(), epoch));

            // test signature verification with different issuer public key
            assertFalse(signature.verify(disclosure2, new IdemixIssuerKey(new String[]{"Attr1, Attr2, Attr3, Attr4, Attr5"}).getIpk(), msg, setup.attrs, 0, setup.ra.getPk(), epoch));

            // test signature verification with different message
            byte[] msg2 = {1, 1, 1};
            assertFalse(signature.verify(disclosure2, setup.key.getIpk(), msg2, setup.attrs, 0, setup.ra.getPk(), epoch));

            // Sign a message with respect to a pseudonym
            IdemixPseudonymSignature nymsig = new IdemixPseudonymSignature(setup.sk, pseudonym, setup.key.getIpk(), msg);
            // check that the pseudonym signature is valid
            assertTrue(nymsig.verify(pseudonym.getNym(), setup.key.getIpk(), msg));

            // Test serialization of IdemixPseudonymSignature
            assertTrue(new IdemixPseudonymSignature(nymsig.toProto()).verify(pseudonym.getNym(), setup.key.getIpk(), msg));
        }

        @Override
        public Boolean call() throws CryptoException {
            for (int i = ITERATIONS; i > 0; --i) {
                test();
            }
            return true;
        }
    }
}
