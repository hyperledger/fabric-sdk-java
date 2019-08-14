/*
 *
 *  Copyright 2017, 2018 IBM Corp. All Rights Reserved.
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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.List;

import com.google.protobuf.ByteString;
import org.apache.milagro.amcl.FP256BN.BIG;
import org.apache.milagro.amcl.FP256BN.ECP;
import org.hyperledger.fabric.protos.idemix.Idemix;
import org.hyperledger.fabric.sdk.exception.CryptoException;

public class RevocationAuthority {
    protected PublicKey pk;
    protected PrivateKey sk;

    public RevocationAuthority(PublicKey pk) {
        this.pk = pk;
    }

    public RevocationAuthority() {
        java.security.KeyPair keyPair = generateLongTermRevocationKey();
        this.pk = keyPair.getPublic();
        this.sk = keyPair.getPrivate();
    }

    /**
     * Creates a Credential Revocation Information object
     *
     * @param unrevokedHandles Array of unrevoked revocation handles
     * @param epoch            The counter (representing a time window) in which this CRI is valid
     * @param alg              Revocation algorithm
     * @return CredentialRevocationInformation object
     */
    public Idemix.CredentialRevocationInformation createCRI(BIG[] unrevokedHandles, int epoch, RevocationAlgorithm alg) throws CryptoException {
        Idemix.CredentialRevocationInformation.Builder builder = Idemix.CredentialRevocationInformation.newBuilder();
        builder.setRevocationAlg(alg.ordinal());
        builder.setEpoch(epoch);

        // Create epoch key
        WeakBB.KeyPair keyPair = WeakBB.weakBBKeyGen();
        if (alg == RevocationAlgorithm.ALG_NO_REVOCATION) {
            // Dummy PK in the proto
            builder.setEpochPk(IdemixUtils.transformToProto(IdemixUtils.genG2));
        } else {
            // Real PK only if we are going to use it
            builder.setEpochPk(IdemixUtils.transformToProto(keyPair.getPk()));
        }

        // Sign epoch + epoch key with the long term key
        byte[] signed;
        try {
            Idemix.CredentialRevocationInformation cri = builder.build();
            Signature ecdsa = Signature.getInstance("SHA256withECDSA");
            ecdsa.initSign(this.sk);
            ecdsa.update(cri.toByteArray());
            signed = ecdsa.sign();

            builder.setEpochPkSig(ByteString.copyFrom(signed));
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new CryptoException("Error processing the signature");
        }

        if (alg == RevocationAlgorithm.ALG_NO_REVOCATION) {
            // build and return the credential information object
            return builder.build();
        } else if (alg == RevocationAlgorithm.ALG_PLAIN_SIGNATURE) {
            // Create revocation object
            Idemix.PlainSigRevocationData.Builder plainSigBuilder = Idemix.PlainSigRevocationData.newBuilder();

            // message signatures object
            Idemix.MessageSignature.Builder messageSigBuilder = Idemix.MessageSignature.newBuilder();

            // Add message signatures to the revocation object
            List<Idemix.MessageSignature> signaturesList = new ArrayList<>();
            for (BIG rh : unrevokedHandles) {
                ECP sig = WeakBB.weakBBSign(keyPair.getSk(), rh);
                messageSigBuilder.setRevocationHandle(ByteString.copyFrom(IdemixUtils.bigToBytes(rh)));
                messageSigBuilder.setRhSignature(IdemixUtils.transformToProto(sig));
                signaturesList.add(messageSigBuilder.build());
            }
            plainSigBuilder.addAllSignatures(signaturesList);

            // Build the revocation data
            byte[] revocationDataBytes = plainSigBuilder.build().toByteArray();
            builder.setRevocationData(ByteString.copyFrom(revocationDataBytes));

            // build and return the credential information object
            return builder.build();
        } else {
            // If alg not supported, throw exception
            throw new IllegalArgumentException("Algorithm " + alg.name() + " not supported");
        }
    }

    /**
     * Verifies that the revocation PK for a certain epoch is valid,
     * by checking that it was signed with the long term revocation key
     *
     * @param epochPK    Epoch PK
     * @param epochPkSig Epoch PK Signature
     * @param epoch      Epoch
     * @param alg        Revocation algorithm
     * @return True if valid
     */
    public boolean verifyEpochPK(Idemix.ECP2 epochPK, byte[] epochPkSig, long epoch, RevocationAlgorithm alg) throws CryptoException {
        Idemix.CredentialRevocationInformation.Builder builder = Idemix.CredentialRevocationInformation.newBuilder();
        builder.setRevocationAlg(alg.ordinal());
        builder.setEpochPk(epochPK);
        builder.setEpoch(epoch);
        Idemix.CredentialRevocationInformation cri = builder.build();
        byte[] bytesTosign = cri.toByteArray();
        try {
            Signature dsa = Signature.getInstance("SHA256withECDSA");
            dsa.initVerify(pk);
            dsa.update(bytesTosign);

            return dsa.verify(epochPkSig);
        } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException e) {
            throw new CryptoException("Error during the EpochPK verification", e);
        }
    }

    public PublicKey getPk() {
        return pk;
    }

    /**
     * Generate a long term ECDSA key pair used for revocation
     *
     * @return Freshly generated ECDSA key pair
     */
    protected java.security.KeyPair generateLongTermRevocationKey() {
        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            SecureRandom random = new SecureRandom();
            AlgorithmParameterSpec params = new ECGenParameterSpec("secp384r1");
            keyGen.initialize(params, random);

            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException e) {
            throw new RuntimeException("Error during the LTRevocation key. Invalid algorithm");
        }
    }

}