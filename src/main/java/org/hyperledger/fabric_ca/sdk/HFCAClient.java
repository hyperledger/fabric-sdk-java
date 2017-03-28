/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

package org.hyperledger.fabric_ca.sdk;

import java.io.File;
import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.net.UnknownHostException;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.JsonWriter;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.bind.DatatypeConverter;

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
import org.apache.http.config.Registry;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.auth.BasicScheme;
import org.apache.http.impl.client.BasicAuthCache;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.ssl.SSLContexts;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.GetTCertBatchRequest;
import org.hyperledger.fabric.sdk.MemberServices;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric_ca.sdk.exception.*;
import sun.security.util.DerValue;
import sun.security.x509.AuthorityKeyIdentifierExtension;
import sun.security.x509.KeyIdentifier;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * HFCAClient Hyperledger Fabric Certificate Authority Client.
 */
public class HFCAClient implements MemberServices {
    private static final Log logger = LogFactory.getLog(HFCAClient.class);
    private static final String HFCA_CONTEXT_ROOT = "/api/v1/cfssl/";
    private static final String HFCA_ENROLL = HFCA_CONTEXT_ROOT + "enroll";
    private static final String HFCA_REGISTER = HFCA_CONTEXT_ROOT + "register";
    private static final String HFCA_REENROLL = HFCA_CONTEXT_ROOT + "reenroll";
    private static final String HFCA_REVOKE = HFCA_CONTEXT_ROOT + "revoke";
    private static final int DEFAULT_SECURITY_LEVEL = 256;  //TODO make configurable //Right now by default FAB services is using
    private static final String DEFAULT_HASH_ALGORITHM = "SHA2";  //Right now by default FAB services is using SHA2


    private static final Set<Integer> VALID_KEY_SIZES =
            Collections.unmodifiableSet(new HashSet<>(Arrays.asList(new Integer[]{256, 384})));

    private final String url;
    private final boolean isSSL;
    private final Properties properties;

    // TODO require use of CryptoPrimitives since we need the generateCertificateRequests methods
    // clean this up when we do have multiple implementations of CryptoSuite
    // see FAB-2628
    private CryptoPrimitives cryptoPrimitives;

    /**
     * HFCAClient constructor
     *
     * @param url        Http URL for the Fabric's certificate authority services endpoint
     * @param properties PEM used for SSL .. not implemented.
     *                   <p>
     *                   Supported properties
     *                   <ul>
     *                   <li>pemFile - File location for x509 pem certificate for SSL.</li>
     *                   <li>allowAllHostNames - boolen(true/false) override certificates CN Host matching -- for development only.</li>
     *                   </ul>
     * @throws MalformedURLException
     */
    public HFCAClient(String url, Properties properties) throws MalformedURLException {
        this.url = url;

        URL purl = new URL(url);
        final String proto = purl.getProtocol();
        if (!"http".equals(proto) && !"https".equals(proto)) {
            throw new IllegalArgumentException("HFCAClient only supports http or https not " + proto);
        }
        final String host = purl.getHost();

        if (StringUtil.isNullOrEmpty(host)) {
            throw new IllegalArgumentException("HFCAClient url needs host");
        }

        final String path = purl.getPath();

        if (!StringUtil.isNullOrEmpty(path)) {

            throw new IllegalArgumentException("HFCAClient url does not support path portion in url remove path: '" + path + "'.");
        }

        final String query = purl.getQuery();

        if (!StringUtil.isNullOrEmpty(query)) {

            throw new IllegalArgumentException("HFCAClient url does not support query portion in url remove query: '" + query + "'.");
        }

        isSSL = "https".equals(proto);


        if (properties != null) {
            this.properties = (Properties) properties.clone(); //keep our own copy.
        } else {
            this.properties = null;
        }

    }

    @Override
    public void setCryptoSuite(CryptoSuite cryptoSuite) {
        this.cryptoPrimitives = (CryptoPrimitives) cryptoSuite;
    }

    @Override
    public CryptoSuite getCryptoSuite() {
        return this.cryptoPrimitives;
    }

    /**
     * Register the user and return an enrollment secret.
     *
     * @param req       Registration request with the following fields: name, role
     * @param registrar The identity of the registrar (i.e. who is performing the registration)
     */
    @Override
    public String register(RegistrationRequest req, User registrar) throws RegistrationException, InvalidArgumentException {

        setUpSSL();

        if (StringUtil.isNullOrEmpty(req.getEnrollmentID())) {
            throw new IllegalArgumentException("EntrollmentID cannot be null or empty");
        }

        if (registrar == null) {
            throw new IllegalArgumentException("Registrar should be a valid member");
        }


        try {
            String body = req.toJson();
            String authHdr = getHTTPAuthCertificate(registrar.getEnrollment(), body);
            JsonObject resp = httpPost(url + HFCA_REGISTER, body, authHdr);
            String secret = resp.getString("secret");
            if (secret == null) {
                throw new Exception("secret was not found in response");
            }
            return secret;
        } catch (Exception e) {

            logger.error(e.getMessage(), e);

            throw new RegistrationException("Error while registering the user. " + e.getMessage(), e);

        }

    }

    /**
     * Enroll the user with member service
     *
     * @param user Enrollment request with the following fields: name, enrollmentSecret
     * @return enrollment
     */
    @Override
    public Enrollment enroll(String user, String secret) throws EnrollmentException, InvalidArgumentException {


        logger.debug(format("enroll user %s", user));

        setUpSSL();


        if (StringUtil.isNullOrEmpty(user)) {
            throw new InvalidArgumentException("enrollment user is not set");
        }
        if (StringUtil.isNullOrEmpty(secret)) {
            throw new InvalidArgumentException("enrollment secret is not set");
        }


        logger.debug("[HFCAClient.enroll] Generating keys...");

        try {
            // generate ECDSA keys: signing and encryption keys
            KeyPair signingKeyPair = cryptoPrimitives.keyGen();
            logger.debug("[HFCAClient.enroll] Generating keys...done!");
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


            logger.debug("[HFCAClient.enroll] Generating keys...done!");


            String responseBody = httpPost(url + HFCA_ENROLL, str,
                    new UsernamePasswordCredentials(user, secret));

            logger.debug("response" + responseBody);

            JsonReader reader = Json.createReader(new StringReader(responseBody));
            JsonObject jsonst = (JsonObject) reader.read();

            boolean success = jsonst.getBoolean("success");
            logger.debug(format("[HFCAClient] enroll success:[%s]", success));

            if (!success) {
                throw new EnrollmentException(format("FabricCA failed enrollment for user %s response success is false.", user));
            }

            JsonObject result = jsonst.getJsonObject("result");
            Base64.Decoder b64dec = Base64.getDecoder();
            String signedPem = new String(b64dec.decode(result.getString("Cert").getBytes(UTF_8)));
            logger.debug(format("[HFCAClient] enroll returned pem:[%s]", signedPem));

            return new HFCAEnrollment(signingKeyPair, cryptoPrimitives.encodePublicKey(signingKeyPair.getPublic()), signedPem);


        } catch (EnrollmentException ee) {
            logger.error(ee.getMessage(), ee);
            throw ee;
        } catch (Exception e) {
            EnrollmentException ee = new EnrollmentException(format("Failed to enroll user %s ", user), e);
            logger.error(e.getMessage(), e);
            throw ee;
        }


    }

    /**
     * Re-Enroll the user with member service
     *
     * @param user user to be re-enrolled
     * @return enrollment
     */
    @Override
    public Enrollment reenroll(User user) throws EnrollmentException, InvalidArgumentException {
        logger.debug(format("re-enroll user %s", user.getName()));

        try {
            setUpSSL();

            KeyPair keypair = new KeyPair(cryptoPrimitives.decodePublicKey(user.getEnrollment().getPublicKey()), user.getEnrollment().getKey());

            // generate CSR
            PKCS10CertificationRequest csr = cryptoPrimitives.generateCertificationRequest(user.getName(), keypair);
            String pem = cryptoPrimitives.certificationRequestToPEM(csr);

            // build request body
            JsonObjectBuilder factory = Json.createObjectBuilder();
            factory.add("certificate_request", pem);
            JsonObject postObject = factory.build();

            StringWriter stringWriter = new StringWriter();
            JsonWriter jsonWriter = Json.createWriter(new PrintWriter(stringWriter));
            jsonWriter.writeObject(postObject);
            jsonWriter.close();
            String body = stringWriter.toString();

            // build authentication header
            String authHdr = getHTTPAuthCertificate(user.getEnrollment(), body);
            JsonObject result = httpPost(url + HFCA_REENROLL, body, authHdr);

            // get new cert from response
            Base64.Decoder b64dec = Base64.getDecoder();
            String signedPem = new String(b64dec.decode(result.getString("Cert").getBytes(UTF_8)));
            logger.debug(format("[HFCAClient] re-enroll returned pem:[%s]", signedPem));

            return new HFCAEnrollment(keypair, user.getEnrollment().getPublicKey(), signedPem);

        } catch (EnrollmentException ee) {
            logger.error(ee.getMessage(), ee);
            throw ee;
        } catch (Exception e) {
            EnrollmentException ee = new EnrollmentException(format("Failed to re-enroll user %s", user), e);
            logger.error(e.getMessage(), e);
            throw ee;
        }
    }

    /**
     * revoke one enrollment of user
     * @param revoker admin user who has revoker attribute configured in CA-server
     * @param enrollment the user enrollment to be revoked
     * @param reason revoke reason, see RFC 5280
     * @throws RevocationException
     * @throws InvalidArgumentException
     */
    @Override
    public void revoke(User revoker, Enrollment enrollment, int reason) throws RevocationException, InvalidArgumentException {

        if (enrollment == null) {
            throw new InvalidArgumentException("revokee enrollment is not set");
        }
        if (revoker == null) {
            throw new InvalidArgumentException("revoker is not set");
        }

        try {
            setUpSSL();

            // get cert from to-be-revoked enrollment
            BufferedInputStream pem = new BufferedInputStream(new ByteArrayInputStream(enrollment.getCert().getBytes()));
            CertificateFactory certFactory = CertificateFactory.getInstance(Config.getConfig().getCertificateFormat());
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(pem);

            // get its serial number
            JsonObjectBuilder factory = Json.createObjectBuilder();
            String serial = DatatypeConverter.printHexBinary(certificate.getSerialNumber().toByteArray());
            factory.add("serial", "0" + serial);

            // get its aki
            // 2.5.29.35 : AuthorityKeyIdentifier
            byte[] var3 = new DerValue(certificate.getExtensionValue("2.5.29.35")).getOctetString();
            AuthorityKeyIdentifierExtension var4 = new AuthorityKeyIdentifierExtension(Boolean.FALSE, var3);
            String aki = DatatypeConverter.printHexBinary(((KeyIdentifier)var4.get("key_id")).getIdentifier());
            factory.add("aki", aki);

            // add reason
            factory.add("reason", reason);

            // build request body
            JsonObject postObject = factory.build();
            StringWriter stringWriter = new StringWriter();
            JsonWriter jsonWriter = Json.createWriter(new PrintWriter(stringWriter));
            jsonWriter.writeObject(postObject);
            jsonWriter.close();
            String body = stringWriter.toString();
            String authHdr = getHTTPAuthCertificate(revoker.getEnrollment(), body);

            // send revoke request
            httpPost(url + HFCA_REVOKE, body, authHdr);
        } catch (CertificateException e) {
            logger.error("Cannot validate certificate. Error is: " + e.getMessage());
            throw new RevocationException("Error while revoking cert. " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw new RevocationException("Error while revoking the user. " + e.getMessage(), e);

        }
    }

    /**
     * revoke one user (including his all enrollments)
     * @param revoker amdin user who has revoker attribute configured in CA-server
     * @param revokee user who is to be revoked
     * @param reason revoke reason, see RFC 5280
     * @throws RevocationException
     * @throws InvalidArgumentException
     */
    @Override
    public void revoke(User revoker, String revokee, int reason) throws RevocationException, InvalidArgumentException {

        logger.debug(format("revoke user %s", revokee));

        if (StringUtil.isNullOrEmpty(revokee)) {
            throw new InvalidArgumentException("revokee user is not set");
        }
        if (revoker == null) {
            throw new InvalidArgumentException("revoker is not set");
        }

        try {
            setUpSSL();

            // build request body
            JsonObjectBuilder factory = Json.createObjectBuilder();
            factory.add("id", revokee);
            factory.add("reason", reason);
            JsonObject postObject = factory.build();
            StringWriter stringWriter = new StringWriter();
            JsonWriter jsonWriter = Json.createWriter(new PrintWriter(stringWriter));
            jsonWriter.writeObject(postObject);
            jsonWriter.close();
            String body = stringWriter.toString();

            // build auth hreader
            String authHdr = getHTTPAuthCertificate(revoker.getEnrollment(), body);

            // send revoke request
            httpPost(url + HFCA_REVOKE, body, authHdr);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw new RevocationException("Error while revoking the user. " + e.getMessage(), e);
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

    private String httpPost(String url, String body, UsernamePasswordCredentials credentials) throws Exception {
        CredentialsProvider provider = new BasicCredentialsProvider();

        provider.setCredentials(AuthScope.ANY, credentials);


        final HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
        httpClientBuilder.setDefaultCredentialsProvider(provider);
        if (registry != null) {


            httpClientBuilder.setConnectionManager(new PoolingHttpClientConnectionManager(registry));

        }

        HttpClient client = httpClientBuilder.build();


        HttpPost httpPost = new HttpPost(url);

        AuthCache authCache = new BasicAuthCache();

        HttpHost targetHost = new HttpHost(httpPost.getURI().getHost(), httpPost.getURI().getPort());

        authCache.put(targetHost, new BasicScheme());

        final HttpClientContext context = HttpClientContext.create();
        context.setCredentialsProvider(provider);

        context.setAuthCache(authCache);

        httpPost.setEntity(new StringEntity(body));
        httpPost.addHeader(new BasicScheme().authenticate(credentials, httpPost, context));

        HttpResponse response = client.execute(httpPost, context);
        int status = response.getStatusLine().getStatusCode();

        HttpEntity entity = response.getEntity();
        String responseBody = entity != null ? EntityUtils.toString(entity) : null;

        if (status >= 400) {

            Exception e = new Exception(format("POST request to %s failed with status code: %d. Response: %s", url, status, responseBody));
            logger.error(e.getMessage());
            throw e;
        }
        logger.debug("Status: " + status);


        return responseBody;
    }

    private JsonObject httpPost(String url, String body, String authHTTPCert) throws Exception {

        HttpPost httpPost = new HttpPost(url);

        final HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
        if (registry != null) {
            httpClientBuilder.setConnectionManager(new PoolingHttpClientConnectionManager(registry));
        }
        HttpClient client = httpClientBuilder.build();

        final HttpClientContext context = HttpClientContext.create();
        httpPost.setEntity(new StringEntity(body));
        httpPost.addHeader("Authorization", authHTTPCert);

        HttpResponse response = client.execute(httpPost, context);
        int status = response.getStatusLine().getStatusCode();

        HttpEntity entity = response.getEntity();
        String responseBody = entity != null ? EntityUtils.toString(entity) : null;

        if (status >= 400) {
            Exception e = new Exception(format("POST request to %s failed with status code: %d. Response: %s", url, status, responseBody));
            logger.error(e.getMessage());
            throw e;
        }
        if (responseBody == null) {

            Exception e = new Exception(format("POST request to %s failed with null response body returned.", url));
            logger.error(e.getMessage());
            throw e;

        }
        logger.debug("Status: " + status);

        JsonReader reader = Json.createReader(new StringReader(responseBody));
        JsonObject jobj = (JsonObject) reader.read();
        boolean success = jobj.getBoolean("success");
        if (!success) {
            EnrollmentException e = new EnrollmentException("Body of response did not contain success", new Exception());
            logger.error(e.getMessage());
            throw e;
        }
        JsonObject result = jobj.getJsonObject("result");
        if (result == null) {
            EnrollmentException e = new EnrollmentException("Body of response did not contain result", new Exception());
            logger.error(e.getMessage());
            throw e;
        }
        return result;
    }

    private String getHTTPAuthCertificate(Enrollment enrollment, String body) throws Exception {
        Base64.Encoder b64 = Base64.getEncoder();
        String cert = b64.encodeToString(enrollment.getCert().getBytes(UTF_8));
        body = b64.encodeToString(body.getBytes(UTF_8));
        String signString = body + "." + cert;
        byte[] signature = cryptoPrimitives.ecdsaSignToBytes(enrollment.getKey(), signString.getBytes(UTF_8));
        return cert + "." + b64.encodeToString(signature);
    }

    /**
     *
     */
    @Override
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


    private Registry<ConnectionSocketFactory> registry = null;


    private void setUpSSL() throws InvalidArgumentException {

        if (isSSL && null == registry) {
            try {

                String pemFile = properties.getProperty("pemFile");
                if (pemFile != null) {

                    cryptoPrimitives.addCACertificateToTrustStore(new File(pemFile), pemFile);

                }

                SSLContext sslContext = SSLContexts.custom()
                        .loadTrustMaterial(cryptoPrimitives.getTrustStore(), null)
                        .build();

                ConnectionSocketFactory sf;
                if (null != properties &&
                        "true".equals(properties.getProperty("allowAllHostNames"))) {
                    AllHostsSSLSocketFactory msf = new AllHostsSSLSocketFactory(cryptoPrimitives.getTrustStore());
                    msf.setHostnameVerifier(SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);
                    sf = msf;
                } else {
                    sf = new SSLConnectionSocketFactory(sslContext);
                }

                registry = RegistryBuilder.<ConnectionSocketFactory>create()
                        .register("https", sf)
                        .register("http", new PlainConnectionSocketFactory())
                        .build();

            } catch (Exception e) {
                logger.error(e);
                throw new InvalidArgumentException(e);
            }
        }

    }

    private class AllHostsSSLSocketFactory extends SSLSocketFactory {
        final SSLContext sslContext = SSLContext.getInstance("TLS");

        AllHostsSSLSocketFactory(KeyStore truststore) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, UnrecoverableKeyException {
            super(truststore);

            TrustManager tm = new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                }

                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                }

                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
            };

            sslContext.init(null, new TrustManager[]{tm}, null);
        }

        @Override
        public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException, UnknownHostException {
            return sslContext.getSocketFactory().createSocket(socket, host, port, autoClose);
        }

        @Override
        public Socket createSocket() throws IOException {
            return sslContext.getSocketFactory().createSocket();
        }
    }

}

