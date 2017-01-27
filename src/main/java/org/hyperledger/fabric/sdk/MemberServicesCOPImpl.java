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

//TODO Need SSL when COP server supports.
//TODO register  -- right now Can test without when COP is primed with admin.
//TODO need to support different hash algorithms and security levels.


import io.netty.util.internal.StringUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.util.encoders.Hex;
import org.hyperledger.fabric.sdk.exception.EnrollmentException;
import org.hyperledger.fabric.sdk.exception.RegistrationException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.JsonWriter;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import static java.lang.String.format;

/**
 * MemberServicesCOPImpl is the default implementation of a member services client.
 */
public class MemberServicesCOPImpl implements MemberServices {
    private static final Log logger = LogFactory.getLog(MemberServicesCOPImpl.class);
    private static final Config config = Config.getConfig();
    private static final String COP_BASEPATH = "/api/v1/cfssl/";
    private static final String COP_ENROLLMENTBASE = COP_BASEPATH + "enroll";


    private static final Set<Integer> VALID_KEY_SIZES =
            Collections.unmodifiableSet(new HashSet<>(Arrays.asList(new Integer[]{256, 384})));

    private final String url;


    private CryptoPrimitives cryptoPrimitives;

    /**
     * MemberServicesCOPImpl constructor
     *
     * @param url URL for the membership services endpoint
     * @param pem PEM used for SSL .. not implemented.
     * @throws CertificateException, MalformedURLException
     */
    public MemberServicesCOPImpl(String url, String pem) throws CertificateException, MalformedURLException {
        this.url = url;

        validateInit();


        this.cryptoPrimitives = new CryptoPrimitives(config.getDefaultHashAlgorithm(), config.getDefaultSecurityLevel());
    }

    private void validateInit() {
        URL purl = null;
        try {
            purl = new URL(url);
        } catch (MalformedURLException e) {
            throw new IllegalArgumentException("MemberServicesCOPImpl invalid url " + url);
        }
        final String proto = purl.getProtocol();
        if (!"http".equals(proto) && !"https".equals(proto)) {
            throw new IllegalArgumentException("MemberServicesCOPImpl only supports http or https not " + proto);
        }
        final String host = purl.getHost();

        if (StringUtil.isNullOrEmpty(host)) {
            throw new IllegalArgumentException("MemberServicesCOPImpl url needs host");
        }

        final String path = purl.getPath();

        if (!StringUtil.isNullOrEmpty(path)) {

            throw new IllegalArgumentException("MemberServicesCOPImpl url does not support path portion in url remove path: '" + path + "'.");
        }

        final String query = purl.getQuery();

        if (!StringUtil.isNullOrEmpty(query)) {

            throw new IllegalArgumentException("MemberServicesCOPImpl url does not support query portion in url remove query: '" + query + "'.");
        }


    }

    /**
     * Get the security level
     *
     * @returns The security level
     */
    public int getSecurityLevel() {
        return cryptoPrimitives.getSecurityLevel();
    }

    /**
     * Set the security level
     *
     * @param securityLevel The security level
     */
    public void setSecurityLevel(int securityLevel) {
        this.cryptoPrimitives.setSecurityLevel(securityLevel);
    }

    /**
     * Get the hash algorithm
     *
     * @returns {string} The hash algorithm
     */
    public String getHashAlgorithm() {
        return this.cryptoPrimitives.getHashAlgorithm();
    }

    /**
     * Set the hash algorithm
     *
     * @param hashAlgorithm The hash algorithm ('SHA2' or 'SHA3')
     */
    public void setHashAlgorithm(String hashAlgorithm) {
        this.cryptoPrimitives.setHashAlgorithm(hashAlgorithm);
    }

    public CryptoPrimitives getCrypto() {
        return this.cryptoPrimitives;
    }

    /**
     * Register the user and return an enrollment secret.
     *
     * @param req       Registration request with the following fields: name, role
     * @param registrar The identity of the registrar (i.e. who is performing the registration)
     */
    public String register(RegistrationRequest req, User registrar) throws RegistrationException {

        //TODO fix once enroll is done.
        throw new RegistrationException("TODO", new IllegalArgumentException("Not yet implemented."));

    }

    /**
     * Enroll the user with member service
     *
     * @param req Enrollment request with the following fields: name, enrollmentSecret
     * @return enrollment
     */
    public Enrollment enroll(EnrollmentRequest req) throws EnrollmentException {


        logger.debug(format("[MemberServicesCOPImpl.enroll] [%s]", req));

        validateEnroll(req);

        final String user = req.getEnrollmentID();
        final String secret = req.getEnrollmentSecret();


        logger.debug("[MemberServicesCOPImpl.enroll] Generating keys...");

        try {
            // generate ECDSA keys: signing and encryption keys
            KeyPair signingKeyPair = cryptoPrimitives.ecdsaKeyGen();
            //  KeyPair encryptionKeyPair = cryptoPrimitives.ecdsaKeyGen();

            PKCS10CertificationRequest csr = cryptoPrimitives.generateCertificationRequest(user, signingKeyPair);
            String pem = cryptoPrimitives.certificationRequestToPEM(csr);
            JsonObjectBuilder factory = Json.createObjectBuilder();
            factory.add("certificate_request", pem);
            JsonObject postObject = factory.build();
            StringWriter stringWriter = new StringWriter();


            JsonWriter jsonWriter = Json.createWriter(new PrintWriter(stringWriter));

            jsonWriter.writeObject(postObject);

            jsonWriter.close();

            String str = stringWriter.toString();


            logger.debug("[MemberServicesCOPImpl.enroll] Generating keys...done!");


            String responseBody = httpPost(url + COP_ENROLLMENTBASE, str,
                    new UsernamePasswordCredentials(user, secret));

            logger.debug("response" + responseBody);

            JsonReader reader = Json.createReader(new StringReader(responseBody));
            JsonObject jsonst = (JsonObject) reader.read();
            String result = jsonst.getString("result");
            boolean success = jsonst.getBoolean("success");
            logger.info(format("[MemberServicesCOPImpl] enroll for user [%s] success:[%s], result:[%s]", user, success, result));

            if (!success) {
                EnrollmentException e = new EnrollmentException(format("Failed to enroll user [%s]  result:[%s]", user, result), new Exception());
                logger.error(e.getMessage());
                throw e;
            }

            Base64.Decoder b64dec = Base64.getDecoder();
            String signedPem = new String(b64dec.decode(result.getBytes()));
            logger.trace(format("[MemberServicesCOPImpl] enroll returned pem:[%s]", signedPem));

            Enrollment enrollment = new Enrollment();
            enrollment.setPrivateKey(signingKeyPair.getPrivate());
            enrollment.setCert(signedPem);
            return enrollment;


        } catch (Exception e) {
            EnrollmentException ee = new EnrollmentException(format("Failed to enroll user %s ", user), e);
            logger.error(ee.getMessage(), ee);
            throw ee;
        }


    }

    private void validateEnroll(EnrollmentRequest req) throws EnrollmentException {
        if (req == null) {

            throw new EnrollmentException("req is not set", new IllegalArgumentException("req is not set"));
        }
        final String user = req.getEnrollmentID();
        final String secret = req.getEnrollmentSecret();
        if (StringUtil.isNullOrEmpty(user)) {
            throw new EnrollmentException("req.enrollmentID is not set", new IllegalArgumentException("req.enrollmentID is not set"));
        }
        if (StringUtil.isNullOrEmpty(secret)) {

            throw new EnrollmentException("req.enrollmentSecret is not set", new IllegalArgumentException("req.enrollmentSecret is not set"));

        }
    }

    /**
     * Http Post Request.
     *
     * @param url         Target URL to POST to.
     * @param body        Body to be sent with the post.
     * @param credentials Credentials to use for basic auth.
     * @return Body of post returned.
     * @throws Exception
     */

    private static String httpPost(String url, String body, UsernamePasswordCredentials credentials) throws Exception {
        CredentialsProvider provider = new BasicCredentialsProvider();


        provider.setCredentials(AuthScope.ANY, credentials);


        HttpClient client = HttpClientBuilder.create().setDefaultCredentialsProvider(provider).build();

        HttpPost httpPost = new HttpPost(url);

        AuthCache authCache = new BasicAuthCache();

        HttpHost targetHost = new HttpHost(httpPost.getURI().getHost(), httpPost.getURI().getPort());

        authCache.put(targetHost, new BasicScheme());

        final HttpClientContext context = HttpClientContext.create();
        context.setCredentialsProvider(provider);
        context.setAuthCache(authCache);

        httpPost.setEntity(new StringEntity(body));

        HttpResponse response = client.execute(httpPost, context);
        int status = response.getStatusLine().getStatusCode();

        HttpEntity entity = response.getEntity();
        String responseBody = entity != null ? EntityUtils.toString(entity) : null;

        if (status >= 400) {

            Exception e = new Exception(format("POST request to %s failed with status code: %d. Response: %s", url, status, responseBody));
            logger.error(e.getMessage());
            throw e;
        }
        logger.debug(format("Successful POST to [%s] Status: ", url, status));


        return responseBody;
    }

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


    /*
     *  Convert a list of member type names to the role mask currently used by the peer
     */
    private int rolesToMask(ArrayList<String> roles) {
        int mask = 0;
        if (roles != null) {
            for (String role : roles) {
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

}

