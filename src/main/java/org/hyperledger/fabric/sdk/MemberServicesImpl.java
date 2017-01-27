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

import java.security.cert.CertificateException;
import java.util.ArrayList;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.sdk.exception.EnrollmentException;
import org.hyperledger.fabric.sdk.exception.RegistrationException;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;

import io.netty.util.internal.StringUtil;

/**
 * MemberServicesImpl is the default implementation of a member services client.
 */
public class MemberServicesImpl implements MemberServices {
	private static final Log logger = LogFactory.getLog(MemberServices.class);

//    private ECAABlockingStub ecaaClient;
//    private ECAPBlockingStub ecapClient;
//    private TCAPBlockingStub tcapClient;
//    private TLSCAPBlockingStub tlscapClient;
    private CryptoPrimitives cryptoPrimitives;

    private int DEFAULT_SECURITY_LEVEL = 256;
	private String DEFAULT_HASH_ALGORITHM = "SHA3";

    /**
     * MemberServicesImpl constructor
     * @param url URL for the membership services endpoint
     * @param pem
     * @throws CertificateException

     */
    public MemberServicesImpl(String url, String pem) throws CertificateException {
    	Endpoint ep = new Endpoint(url, pem);

//    	this.ecaaClient = ECAAGrpc.newBlockingStub(ep.getChannelBuilder().build());
//    	this.ecapClient = ECAPGrpc.newBlockingStub(ep.getChannelBuilder().build());
//    	this.tcapClient = TCAPGrpc.newBlockingStub(ep.getChannelBuilder().build());
//    	this.tlscapClient = TLSCAPGrpc.newBlockingStub(ep.getChannelBuilder().build());
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
    public String register(RegistrationRequest req, User registrar) throws RegistrationException {
    	if (StringUtil.isNullOrEmpty(req.getEnrollmentID())) {
    		throw new IllegalArgumentException("EntrollmentID cannot be null or empty");
    	}

    	if (registrar == null) {
    		throw new IllegalArgumentException("Registrar should be a valid member");
    	}

    	return ""; //TODO remove 

//    	Registrar reg = Registrar.newBuilder()
//    			.setId(
//    					Identity.newBuilder()
//    					.setId(registrar.getName())
//    					.build())
//    			.build(); //TODO: set Roles and Delegate Roles
//
//    	RegisterUserReq.Builder regReqBuilder = RegisterUserReq.newBuilder();
//    	regReqBuilder.setId(
//    					Identity.newBuilder()
//    					.setId(req.getEnrollmentID())
//    					.build());
//    	regReqBuilder.setRoleValue(rolesToMask(req.getRoles()));
//    	regReqBuilder.setAffiliation(req.getAffiliation());
//    	regReqBuilder.setRegistrar(reg);
//
//    	RegisterUserReq registerReq = regReqBuilder.build();
//    	byte[] buffer = registerReq.toByteArray();
//
//    	try {
//			PrivateKey signKey = cryptoPrimitives.ecdsaKeyFromPrivate(Hex.decode(registrar.getEnrollment().getKey()));
//	    	logger.debug("Retreived private key");
//			byte[][] signature = cryptoPrimitives.ecdsaSign(signKey, buffer);
//	    	logger.debug("Signed the request with key");
//			Signature sig = Signature.newBuilder().setType(CryptoType.ECDSA).setR(ByteString.copyFrom(signature[0])).setS(ByteString.copyFrom(signature[1])).build();
//			regReqBuilder.setSig(sig);
//	    	logger.debug("Now sendingt register request");
//			Token token = this.ecaaClient.registerUser(regReqBuilder.build());
//			return token.getTok().toStringUtf8();
//
//		} catch (Exception e) {
//			throw new RegistrationException("Error while registering the user", e);
//		}

    }

	/**
     * Enroll the member with member service
     * @param req Enrollment request with the following fields: name, enrollmentSecret
     * @return enrollment
     */
//    public Enrollment enroll(EnrollmentRequest req) throws EnrollmentException {
//
//
//        logger.debug(String.format("[MemberServicesImpl.enroll] [%s]", req));
//        if (StringUtil.isNullOrEmpty(req.getEnrollmentID())) { throw new RuntimeException("req.enrollmentID is not set");}
//        if (StringUtil.isNullOrEmpty(req.getEnrollmentSecret())) { throw new RuntimeException("req.enrollmentSecret is not set");}
//
//        logger.debug("[MemberServicesImpl.enroll] Generating keys...");
//
//        try {
//	        // generate ECDSA keys: signing and encryption keys
//	        KeyPair signingKeyPair = cryptoPrimitives.ecdsaKeyGen();
//	        KeyPair encryptionKeyPair = cryptoPrimitives.ecdsaKeyGen();
//
//	        logger.debug("[MemberServicesImpl.enroll] Generating keys...done!");
//
//	        // create the proto message
//	        ECertCreateReq.Builder eCertCreateRequestBuilder = ECertCreateReq.newBuilder()
//	        		.setTs(Timestamp.newBuilder().setSeconds(new java.util.Date().getTime()))
//	        		.setId(Identity.newBuilder()
//	    					.setId(req.getEnrollmentID())
//	    					.build())
//	        		.setTok(Token.newBuilder().setTok(ByteString.copyFrom(req.getEnrollmentSecret(), "UTF8")))
//	        		.setSign(PublicKey.newBuilder().setKey(ByteString.copyFrom(signingKeyPair.getPublic().getEncoded())).setType(CryptoType.ECDSA))
//	        		.setEnc(PublicKey.newBuilder().setKey(ByteString.copyFrom(encryptionKeyPair.getPublic().getEncoded())).setType(CryptoType.ECDSA));
//
//	        ECertCreateResp eCertCreateResp = this.ecapClient.createCertificatePair(eCertCreateRequestBuilder.build());
//
//	        byte[] cipherText = eCertCreateResp.getTok().getTok().toByteArray();
//            byte[] decryptedTokBytes = cryptoPrimitives.eciesDecrypt(encryptionKeyPair, cipherText);
//
//            eCertCreateRequestBuilder = eCertCreateRequestBuilder
//            		.setTok(Token.newBuilder().setTok(ByteString.copyFrom(decryptedTokBytes)));
//
//            ECertCreateReq certReq = eCertCreateRequestBuilder.buildPartial();
//            byte[] buf = certReq.toByteArray();
//
//            byte[][] sig = cryptoPrimitives.ecdsaSign(signingKeyPair.getPrivate(), buf);
//            Signature protoSig = Signature.newBuilder().setType(CryptoType.ECDSA).setR(ByteString.copyFrom(sig[0])).setS(ByteString.copyFrom(sig[1])).build();
//            eCertCreateRequestBuilder = eCertCreateRequestBuilder.setSig(protoSig);
//
//            eCertCreateResp = ecapClient.createCertificatePair(eCertCreateRequestBuilder.build());
//
//            logger.debug("[MemberServicesImpl.enroll] eCertCreateResp : [%s]" + eCertCreateResp.toByteString());
//
//            Enrollment enrollment = new Enrollment();
//            enrollment.setKey(Hex.toHexString(signingKeyPair.getPrivate().getEncoded()));
//            enrollment.setCert(Hex.toHexString(eCertCreateResp.getCerts().getSign().toByteArray()));
//            enrollment.setChainKey(Hex.toHexString(eCertCreateResp.getPkchain().toByteArray()));
//
//            logger.debug("Enrolled successfully: "+enrollment);
//            return enrollment;
//
//        } catch (Exception e) {
//			throw new EnrollmentException("Failed to enroll user", e);
//		}
//
//
//    }

    /**
     *
     */
    public void getTCertBatch(GetTCertBatchRequest req) {

    	/*TODO implement getTCertBatch
        let self = this;
        cb = cb || nullCB;

        let timestamp = sdk_util.GenerateTimestamp();

        // create the proto
        let tCertCreateSetReq = new _caProto.TCertCreateSetReq();
        tCertCreateSetReq.setTs(timestamp);
        tCertCreateSetReq.setId({id: req.name});
        tCertCreateSetReq.setNum(req.num);
        if (req.attrs) {
            let attrs = [];
            for (let i = 0; i < req.attrs.length; i++) {
                attrs.push({attributeName:req.attrs[i]});
            }
            tCertCreateSetReq.setAttributes(attrs);
        }

        // serialize proto
        let buf = tCertCreateSetReq.toBuffer();

        // sign the transaction using enrollment key
        let signKey = self.cryptoPrimitives.ecdsaKeyFromPrivate(req.enrollment.key, "hex");
        let sig = self.cryptoPrimitives.ecdsaSign(signKey, buf);

        tCertCreateSetReq.setSig(new _caProto.Signature(
            {
                type: _caProto.CryptoType.ECDSA,
                r: new Buffer(sig.r.toString()),
                s: new Buffer(sig.s.toString())
            }
        ));

        // send the request
        self.tcapClient.createCertificateSet(tCertCreateSetReq, function (err, resp) {
            if (err) return cb(err);
            // logger.debug('tCertCreateSetResp:\n', resp);
            cb(null, self.processTCertBatch(req, resp));
        });

        */
    }

    /**
     * Process a batch of tcerts after having retrieved them from the TCA.
     */
//    private Ca.TCert[] processTCertBatch(GetTCertBatchRequest req, Object resp) {

//    	return null;

    	/* TODO implement processTCertBatch
        //
        // Derive secret keys for TCerts
        //

        let enrollKey = req.enrollment.key;
        let tCertOwnerKDFKey = resp.certs.key;
        let tCerts = resp.certs.certs;

        let byte1 = new Buffer(1);
        byte1.writeUInt8(0x1, 0);
        let byte2 = new Buffer(1);
        byte2.writeUInt8(0x2, 0);

        let tCertOwnerEncryptKey = self.cryptoPrimitives.hmac(tCertOwnerKDFKey, byte1).slice(0, 32);
        let expansionKey = self.cryptoPrimitives.hmac(tCertOwnerKDFKey, byte2);

        let tCertBatch:TCert[] = [];

        // Loop through certs and extract private keys
        for (var i = 0; i < tCerts.length; i++) {
            var tCert = tCerts[i];
            let x509Certificate;
            try {
                x509Certificate = new crypto.X509Certificate(tCert.cert);
            } catch (ex) {
                logger.debug("Warning: problem parsing certificate bytes; retrying ... ", ex);
                continue;
            }

            // logger.debug("HERE2: got x509 cert");
            // extract the encrypted bytes from extension attribute
            let tCertIndexCT = x509Certificate.criticalExtension(crypto.TCertEncTCertIndex);
            // logger.debug('tCertIndexCT: ',JSON.stringify(tCertIndexCT));
            let tCertIndex = self.cryptoPrimitives.aesCBCPKCS7Decrypt(tCertOwnerEncryptKey, tCertIndexCT);
            // logger.debug('tCertIndex: ',JSON.stringify(tCertIndex));

            let expansionValue = self.cryptoPrimitives.hmac(expansionKey, tCertIndex);
            // logger.debug('expansionValue: ',expansionValue);

            // compute the private key
            let one = new BN(1);
            let k = new BN(expansionValue);
            let n = self.cryptoPrimitives.ecdsaKeyFromPrivate(enrollKey, "hex").ec.curve.n.sub(one);
            k = k.mod(n).add(one);

            let D = self.cryptoPrimitives.ecdsaKeyFromPrivate(enrollKey, "hex").getPrivate().add(k);
            let pubHex = self.cryptoPrimitives.ecdsaKeyFromPrivate(enrollKey, "hex").getPublic("hex");
            D = D.mod(self.cryptoPrimitives.ecdsaKeyFromPublic(pubHex, "hex").ec.curve.n);

            // Put private and public key in returned tcert
            let tcert = new TCert(tCert.cert, self.cryptoPrimitives.ecdsaKeyFromPrivate(D, "hex"));
            tCertBatch.push(tcert);
        }

        if (tCertBatch.length == 0) {
            throw new RuntimeException("Failed fetching TCertBatch. No valid TCert received.");
        }

        return tCertBatch;
        */

 //   } // end processTCertBatch

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

	@Override
	public Enrollment enroll(EnrollmentRequest req) throws EnrollmentException {
		// TODO Auto-generated method stub
		return null;
	}
}

