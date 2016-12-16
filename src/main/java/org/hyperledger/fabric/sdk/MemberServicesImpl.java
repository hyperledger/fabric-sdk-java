/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 	  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk;

import com.google.protobuf.ByteString;
import com.google.protobuf.Timestamp;
import io.netty.util.internal.StringUtil;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.EnrollmentException;
import org.hyperledger.fabric.sdk.exception.GetTCertBatchException;
import org.hyperledger.fabric.sdk.exception.RegistrationException;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;
import org.hyperledger.protos.*;
import org.hyperledger.protos.Ca.*;
import org.hyperledger.protos.Ca.Identity;
import org.hyperledger.protos.Ca.PublicKey;
import org.hyperledger.protos.Ca.Signature;
import org.hyperledger.protos.ECAAGrpc.ECAABlockingStub;
import org.hyperledger.protos.ECAPGrpc.ECAPBlockingStub;
import org.hyperledger.protos.TCAPGrpc.TCAPBlockingStub;
import org.hyperledger.protos.TLSCAPGrpc.TLSCAPBlockingStub;
import sun.security.util.DerInputStream;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

/**
 * MemberServicesImpl is the default implementation of a member services client.
 */
public class MemberServicesImpl implements MemberServices {
	private static final Log logger = LogFactory.getLog(MemberServices.class);

    private ECAABlockingStub ecaaClient;
    private ECAPBlockingStub ecapClient;
    private TCAPBlockingStub tcapClient;
    private TLSCAPBlockingStub tlscapClient;
    private CryptoPrimitives cryptoPrimitives;

    private int DEFAULT_SECURITY_LEVEL = 256;
	private String DEFAULT_HASH_ALGORITHM = "SHA3";

    private static final String TCERT_ENC_TCERT_INDEX = "1.2.3.4.5.6.7";

    /**
     * MemberServicesImpl constructor
     * @param url URL for the membership services endpoint
     * @param pem
     * @throws CertificateException

     */
    public MemberServicesImpl(String url, String pem) throws CertificateException {
    	Endpoint ep = new Endpoint(url, pem);

    	this.ecaaClient = ECAAGrpc.newBlockingStub(ep.getChannelBuilder().build());
    	this.ecapClient = ECAPGrpc.newBlockingStub(ep.getChannelBuilder().build());
    	this.tcapClient = TCAPGrpc.newBlockingStub(ep.getChannelBuilder().build());
    	this.tlscapClient = TLSCAPGrpc.newBlockingStub(ep.getChannelBuilder().build());
    	this.cryptoPrimitives = new CryptoPrimitives(DEFAULT_HASH_ALGORITHM, DEFAULT_SECURITY_LEVEL);

    }

    /**
     * Get the security level
     * @returns The security level
     */
    public int getSecurityLevel() {
        return cryptoPrimitives.getSecurityLevel();
    }

    /**
     * Set the security level
     * @params securityLevel The security level
     */
    public void setSecurityLevel(int securityLevel) {
        this.cryptoPrimitives.setSecurityLevel(securityLevel);
    }

    /**
     * Get the hash algorithm
     * @returns {string} The hash algorithm
     */
    public String getHashAlgorithm() {
        return this.cryptoPrimitives.getHashAlgorithm();
    }

    /**
     * Set the hash algorithm
     * @params hashAlgorithm The hash algorithm ('SHA2' or 'SHA3')
     */
    public void setHashAlgorithm(String hashAlgorithm) {
        this.cryptoPrimitives.setHashAlgorithm(hashAlgorithm);
    }

    public CryptoPrimitives getCrypto() {
        return this.cryptoPrimitives;
    }

    /**
     * Register the member and return an enrollment secret.
     * @param req Registration request with the following fields: name, role
     * @param registrar The identity of the registrar (i.e. who is performing the registration)
     */
    public String register(RegistrationRequest req, Member registrar) throws RegistrationException {
    	if (StringUtil.isNullOrEmpty(req.getEnrollmentID())) {
    		throw new IllegalArgumentException("EntrollmentID cannot be null or empty");
    	}

    	if (registrar == null) {
    		throw new IllegalArgumentException("Registrar should be a valid member");
    	}


    	Registrar reg = Registrar.newBuilder()
    			.setId(
    					Identity.newBuilder()
    					.setId(registrar.getName())
    					.build())
    			.build(); //TODO: set Roles and Delegate Roles

    	RegisterUserReq.Builder regReqBuilder = RegisterUserReq.newBuilder();
    	regReqBuilder.setId(
    					Identity.newBuilder()
    					.setId(req.getEnrollmentID())
    					.build());
    	regReqBuilder.setRoleValue(rolesToMask(req.getRoles()));
    	regReqBuilder.setAffiliation(req.getAffiliation());
    	regReqBuilder.setRegistrar(reg);

    	RegisterUserReq registerReq = regReqBuilder.build();
    	byte[] buffer = registerReq.toByteArray();

    	try {
            java.security.PrivateKey signKey = cryptoPrimitives.ecdsaKeyFromPrivate(Hex.decode(registrar.getEnrollment().getKey()));
	    	logger.debug("Retreived private key");
            BigInteger[] signature = cryptoPrimitives.ecdsaSign(signKey, buffer);
	    	logger.debug("Signed the request with key");
            Signature sig = Signature.newBuilder().setType(CryptoType.ECDSA).setR(ByteString.copyFrom(signature[0].toString().getBytes())).setS(ByteString.copyFrom(signature[1].toString().getBytes())).build();
			regReqBuilder.setSig(sig);
	    	logger.debug("Now sendingt register request");
			Token token = this.ecaaClient.registerUser(regReqBuilder.build());
			return token.getTok().toStringUtf8();

		} catch (Exception e) {
			throw new RegistrationException("Error while registering the user", e);
		}

    }

	/**
     * Enroll the member with member service
     * @param req Enrollment request with the following fields: name, enrollmentSecret
     * @return enrollment
     */
    public Enrollment enroll(EnrollmentRequest req) throws EnrollmentException {
        logger.debug(String.format("[MemberServicesImpl.enroll] [%s]", req));
        if (StringUtil.isNullOrEmpty(req.getEnrollmentID())) { throw new RuntimeException("req.enrollmentID is not set");}
        if (StringUtil.isNullOrEmpty(req.getEnrollmentSecret())) { throw new RuntimeException("req.enrollmentSecret is not set");}

        logger.debug("[MemberServicesImpl.enroll] Generating keys...");

        try {
	        // generate ECDSA keys: signing and encryption keys
	        KeyPair signingKeyPair = cryptoPrimitives.ecdsaKeyGen();
	        KeyPair encryptionKeyPair = cryptoPrimitives.ecdsaKeyGen();

	        logger.debug("[MemberServicesImpl.enroll] Generating keys...done!");

	        // create the proto message
	        ECertCreateReq.Builder eCertCreateRequestBuilder = ECertCreateReq.newBuilder()
	        		.setTs(Timestamp.newBuilder().setSeconds(new java.util.Date().getTime()))
	        		.setId(Identity.newBuilder()
	    					.setId(req.getEnrollmentID())
	    					.build())
	        		.setTok(Token.newBuilder().setTok(ByteString.copyFrom(req.getEnrollmentSecret(), "UTF8")))
	        		.setSign(PublicKey.newBuilder().setKey(ByteString.copyFrom(signingKeyPair.getPublic().getEncoded())).setType(CryptoType.ECDSA))
	        		.setEnc(PublicKey.newBuilder().setKey(ByteString.copyFrom(encryptionKeyPair.getPublic().getEncoded())).setType(CryptoType.ECDSA));

	        ECertCreateResp eCertCreateResp = this.ecapClient.createCertificatePair(eCertCreateRequestBuilder.build());

	        byte[] cipherText = eCertCreateResp.getTok().getTok().toByteArray();
            byte[] decryptedTokBytes = cryptoPrimitives.eciesDecrypt(encryptionKeyPair, cipherText);

            eCertCreateRequestBuilder = eCertCreateRequestBuilder
            		.setTok(Token.newBuilder().setTok(ByteString.copyFrom(decryptedTokBytes)));

            ECertCreateReq certReq = eCertCreateRequestBuilder.buildPartial();
            byte[] buf = certReq.toByteArray();

            BigInteger[] sig = cryptoPrimitives.ecdsaSign(signingKeyPair.getPrivate(), buf);
            Signature protoSig = Signature.newBuilder().setType(CryptoType.ECDSA).setR(ByteString.copyFrom(sig[0].toString().getBytes())).setS(ByteString.copyFrom(sig[1].toString().getBytes())).build();
            eCertCreateRequestBuilder = eCertCreateRequestBuilder.setSig(protoSig);

            eCertCreateResp = ecapClient.createCertificatePair(eCertCreateRequestBuilder.build());

            logger.debug("[MemberServicesImpl.enroll] eCertCreateResp : [%s]" + eCertCreateResp.toByteString());

            Enrollment enrollment = new Enrollment();
            enrollment.setKey(Hex.toHexString(signingKeyPair.getPrivate().getEncoded()));
            enrollment.setCert(Hex.toHexString(eCertCreateResp.getCerts().getSign().toByteArray()));
            enrollment.setChainKey(Hex.toHexString(eCertCreateResp.getPkchain().toByteArray()));
            enrollment.setQueryStateKey(Hex.toHexString(cryptoPrimitives.generateNonce()));

            logger.debug("Enrolled successfully: "+enrollment);
            return enrollment;

        } catch (Exception e) {
			throw new EnrollmentException("Failed to enroll user", e);
		}
    }

    /**
     * Get an array of transaction certificates (tcerts).
     * @param req Request of the form: name, enrollment, num
     * @return enrollment
     */
    public List<TCert> getTCertBatch(GetTCertBatchRequest req) throws GetTCertBatchException {
        logger.debug(String.format("[MemberServicesImpl.getTCertBatch] [%s]", req));

        try {
            // create the proto
            TCertCreateSetReq.Builder tCertCreateSetReq = TCertCreateSetReq.newBuilder()
                    .setTs(Timestamp.newBuilder().setSeconds(new java.util.Date().getTime()))
                    .setId(Identity.newBuilder().setId(req.getName()))
                    .setNum(req.getNum());

            if (req.getAttrs() != null) {
                for (String attr : req.getAttrs()) {
                    tCertCreateSetReq.addAttributes(TCertAttribute.newBuilder().setAttributeName(attr).build());
                }
            }

            // serialize proto
            byte[] buf = tCertCreateSetReq.buildPartial().toByteArray();

            // sign the transaction using enrollment key
            java.security.PrivateKey signKey = cryptoPrimitives.ecdsaKeyFromPrivate(Hex.decode(req.getEnrollment().getKey()));
            BigInteger[] sig = cryptoPrimitives.ecdsaSign(signKey, buf);
            Signature protoSig = Signature.newBuilder().setType(CryptoType.ECDSA).setR(ByteString.copyFrom(sig[0].toString().getBytes())).setS(ByteString.copyFrom(sig[1].toString().getBytes())).build();
            tCertCreateSetReq.setSig(protoSig);

            // send the request
            TCertCreateSetResp tCertCreateSetResp = tcapClient.createCertificateSet(tCertCreateSetReq.build());
            logger.debug("[MemberServicesImpl.getTCertBatch] tCertCreateSetResp : [%s]" + tCertCreateSetResp.toByteString());

            return processTCertBatch(req, tCertCreateSetResp);
        } catch (Exception e) {
            throw new GetTCertBatchException("Failed to get tcerts", e);
        }
    }

    /**
     * Process a batch of tcerts after having retrieved them from the TCA.
     */
    private List<TCert> processTCertBatch(GetTCertBatchRequest req, TCertCreateSetResp resp)
            throws NoSuchPaddingException, InvalidKeyException, NoSuchAlgorithmException,
            IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException, CryptoException, IOException {
        String enrollKey = req.getEnrollment().getKey();
        byte[] tCertOwnerKDFKey = resp.getCerts().getKey().toByteArray();
        List<Ca.TCert> tCerts = resp.getCerts().getCertsList();

        byte[] byte1 = new byte[]{1};
        byte[] byte2 = new byte[]{2};

        byte[] tCertOwnerEncryptKey = Arrays.copyOfRange(cryptoPrimitives.calculateMac(tCertOwnerKDFKey, byte1), 0, 32);
        byte[] expansionKey = cryptoPrimitives.calculateMac(tCertOwnerKDFKey, byte2);

        List<TCert> tCertBatch = new ArrayList<>(tCerts.size());

        // Loop through certs and extract private keys
        for (Ca.TCert tCert : tCerts) {
            X509Certificate x509Certificate;
            try {
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                x509Certificate = (X509Certificate)cf.generateCertificate(tCert.getCert().newInput());
            } catch (Exception ex) {
                logger.debug("Warning: problem parsing certificate bytes; retrying ... ", ex);
                continue;
            }

            // extract the encrypted bytes from extension attribute
            byte[] tCertIndexCT = fromDer(x509Certificate.getExtensionValue(TCERT_ENC_TCERT_INDEX));
            byte[] tCertIndex = cryptoPrimitives.aesCBCPKCS7Decrypt(tCertOwnerEncryptKey, tCertIndexCT);

            byte[] expansionValue = cryptoPrimitives.calculateMac(expansionKey, tCertIndex);

            // compute the private key
            BigInteger k = new BigInteger(1, expansionValue);
            BigInteger n = ((ECPrivateKey)cryptoPrimitives.ecdsaKeyFromPrivate(Hex.decode(enrollKey)))
                    .getParameters().getN().subtract(BigInteger.ONE);
            k = k.mod(n).add(BigInteger.ONE);

            BigInteger D = ((ECPrivateKey) cryptoPrimitives.ecdsaKeyFromPrivate(Hex.decode(enrollKey))).getD().add(k);
            D = D.mod(((ECPrivateKey)cryptoPrimitives.ecdsaKeyFromPrivate(Hex.decode(enrollKey))).getParameters().getN());

            // Put private and public key in returned tcert
            TCert tcert = new TCert(tCert.getCert().toByteArray(), cryptoPrimitives.ecdsaKeyFromBigInt(D));

            tCertBatch.add(tcert);
        }

        if (tCertBatch.size() == 0) {
            throw new RuntimeException("Failed fetching TCertBatch. No valid TCert received.");
        }

        return tCertBatch;
    }

    /*
     *  Convert a list of member type names to the role mask currently used by the peer
     */
    private int rolesToMask(ArrayList<String> roles) {
        int mask = 0;
        if (roles != null) {
            for (String role: roles) {
                switch (role) {
                    case "client":
                        mask |= 1;
                        break;       // Client mask
                    case "peer":
                        mask |= 2;
                        break;       // Peer mask
                    case "validator":
                        mask |= 4;
                        break;  // Validator mask
                    case "auditor":
                        mask |= 8;
                        break;    // Auditor mask
                }
            }
        }

        if (mask == 0) mask = 1;  // Client
        return mask;
    }

    private byte[] fromDer(byte[] data) throws IOException {
        DerInputStream dis = new DerInputStream(data);
        return dis.getOctetString();
    }
}

