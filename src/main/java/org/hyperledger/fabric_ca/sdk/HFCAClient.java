/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *        http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric_ca.sdk;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.StringReader;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Properties;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonReader;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.bind.DatatypeConverter;

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
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.helper.Utils;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric_ca.sdk.exception.RegistrationException;
import org.hyperledger.fabric_ca.sdk.exception.RevocationException;
import org.hyperledger.fabric_ca.sdk.helper.Config;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * HFCAClient Hyperledger Fabric Certificate Authority Client.
 */
@SuppressWarnings ("deprecation")
public class HFCAClient {
    private static final Log logger = LogFactory.getLog(HFCAClient.class);
    Config config = Config.getConfig(); //Load config so enable logging setting.
    private static final String HFCA_CONTEXT_ROOT = "/api/v1/";
    private static final String HFCA_ENROLL = HFCA_CONTEXT_ROOT + "enroll";
    private static final String HFCA_REGISTER = HFCA_CONTEXT_ROOT + "register";
    private static final String HFCA_REENROLL = HFCA_CONTEXT_ROOT + "reenroll";
    private static final String HFCA_REVOKE = HFCA_CONTEXT_ROOT + "revoke";

    static final String FABRIC_CA_REQPROP = "caname";

    private final String url;
    private final boolean isSSL;
    private final Properties properties;
    private final String name;

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
    HFCAClient(String name, String url, Properties properties) throws MalformedURLException {
        logger.debug(format("new HFCAClient %s", url));
        this.url = url;

        this.name = name; //name may be null

        URL purl = new URL(url);
        final String proto = purl.getProtocol();
        if (!"http".equals(proto) && !"https".equals(proto)) {
            throw new IllegalArgumentException("HFCAClient only supports http or https not " + proto);
        }
        final String host = purl.getHost();

        if (Utils.isNullOrEmpty(host)) {
            throw new IllegalArgumentException("HFCAClient url needs host");
        }

        final String path = purl.getPath();

        if (!Utils.isNullOrEmpty(path)) {

            throw new IllegalArgumentException("HFCAClient url does not support path portion in url remove path: '" + path + "'.");
        }

        final String query = purl.getQuery();

        if (!Utils.isNullOrEmpty(query)) {

            throw new IllegalArgumentException("HFCAClient url does not support query portion in url remove query: '" + query + "'.");
        }

        isSSL = "https".equals(proto);

        if (properties != null) {
            this.properties = (Properties) properties.clone(); //keep our own copy.
        } else {
            this.properties = null;
        }

    }

    public static HFCAClient createNewInstance(String url, Properties properties) throws MalformedURLException {

        return new HFCAClient(null, url, properties);

    }

    public static HFCAClient createNewInstance(String name, String url, Properties properties) throws MalformedURLException, InvalidArgumentException {

        if (name == null || name.isEmpty()) {

            throw new InvalidArgumentException("name must not be null or an empty string.");
        }

        return new HFCAClient(name, url, properties);

    }

    public void setCryptoSuite(CryptoSuite cryptoSuite) {
        this.cryptoPrimitives = (CryptoPrimitives) cryptoSuite;
        try {
            cryptoPrimitives.init();
        } catch (Exception e) {
            logger.error(e);
        }
    }

    public CryptoSuite getCryptoSuite() {
        return cryptoPrimitives;
    }

    /**
     * Register a user.
     *
     * @param request   Registration request with the following fields: name, role.
     * @param registrar The identity of the registrar (i.e. who is performing the registration).
     * @return the enrollment secret.
     * @throws RegistrationException    if registration fails.
     * @throws InvalidArgumentException
     */

    public String register(RegistrationRequest request, User registrar) throws RegistrationException, InvalidArgumentException {

        if (Utils.isNullOrEmpty(request.getEnrollmentID())) {
            throw new InvalidArgumentException("EntrollmentID cannot be null or empty");
        }

        if (registrar == null) {
            throw new InvalidArgumentException("Registrar should be a valid member");
        }
        logger.debug(format("register  url: %s, registrar: %s", url, registrar.getName()));

        setUpSSL();

        try {
            String body = request.toJson();
            String authHdr = getHTTPAuthCertificate(registrar.getEnrollment(), body);
            JsonObject resp = httpPost(url + HFCA_REGISTER, body, authHdr);
            String secret = resp.getString("secret");
            if (secret == null) {
                throw new Exception("secret was not found in response");
            }
            logger.debug(format("register  url: %s, registrar: %s done.", url, registrar));
            return secret;
        } catch (Exception e) {

            RegistrationException registrationException = new RegistrationException(format("Error while registering the user %s url: %s  %s ", registrar, url, e.getMessage()), e);
            logger.error(registrar);
            throw registrationException;

        }

    }

    /**
     * Enroll the user with member service
     *
     * @param user   Identity name to enroll
     * @param secret Secret returned via registration
     * @return enrollment
     * @throws EnrollmentException
     * @throws InvalidArgumentException
     */
    public Enrollment enroll(String user, String secret) throws EnrollmentException, InvalidArgumentException {
        return enroll(user, secret, new EnrollmentRequest());
    }

    /**
     * Enroll the user with member service
     *
     * @param user   Identity name to enroll
     * @param secret Secret returned via registration
     * @param req    Enrollment request with the following fields: hosts, profile, csr, label, keypair
     * @return enrollment
     * @throws EnrollmentException
     * @throws InvalidArgumentException
     */

    public Enrollment enroll(String user, String secret, EnrollmentRequest req) throws EnrollmentException, InvalidArgumentException {

        logger.debug(format("url:%s enroll user: %s", url, user));

        if (Utils.isNullOrEmpty(user)) {
            throw new InvalidArgumentException("enrollment user is not set");
        }
        if (Utils.isNullOrEmpty(secret)) {
            throw new InvalidArgumentException("enrollment secret is not set");
        }

        setUpSSL();

        try {
            String pem = req.getCsr();
            KeyPair keypair = req.getKeyPair();
            if (null != pem && keypair == null) {
                throw new InvalidArgumentException("If certificate signing request is supplied the key pair needs to be supplied too.");
            }
            if (keypair == null) {
                logger.debug("[HFCAClient.enroll] Generating keys...");

                // generate ECDSA keys: signing and encryption keys
                keypair = cryptoPrimitives.keyGen();

                logger.debug("[HFCAClient.enroll] Generating keys...done!");
            }

            if (pem == null) {
                PKCS10CertificationRequest csr = cryptoPrimitives.generateCertificationRequest(user, keypair);
                pem = cryptoPrimitives.certificationRequestToPEM(csr);
                req.setCSR(pem);
            }

            if (name != null && !name.isEmpty()) {
                req.setCAName(name);
            }
            String body = req.toJson();

            String responseBody = httpPost(url + HFCA_ENROLL, body,
                    new UsernamePasswordCredentials(user, secret));

            logger.debug("response:" + responseBody);

            JsonReader reader = Json.createReader(new StringReader(responseBody));
            JsonObject jsonst = (JsonObject) reader.read();

            boolean success = jsonst.getBoolean("success");
            logger.debug(format("[HFCAClient] enroll success:[%s]", success));

            if (!success) {
                throw new EnrollmentException(format("FabricCA failed enrollment for user %s response success is false.", user));
            }

            JsonObject result = jsonst.getJsonObject("result");
            if (result == null) {
                throw new EnrollmentException(format("FabricCA failed enrollment for user %s - response did not contain a result", user));
            }

            Base64.Decoder b64dec = Base64.getDecoder();

            String signedPem = new String(b64dec.decode(result.getString("Cert").getBytes(UTF_8)));
            logger.debug(format("[HFCAClient] enroll returned pem:[%s]", signedPem));

            JsonArray messages = jsonst.getJsonArray("messages");
            if (messages != null && !messages.isEmpty()) {
                JsonObject jo = messages.getJsonObject(0);
                String message = format("Enroll request response message [code %d]: %s", jo.getInt("code"), jo.getString("message"));
                logger.info(message);
            }
            logger.debug("Enrollment done.");

            return new HFCAEnrollment(keypair, signedPem);

        } catch (EnrollmentException ee) {
            logger.error(format("url:%s, user:%s  error:%s", url, user, ee.getMessage()), ee);
            throw ee;
        } catch (Exception e) {
            EnrollmentException ee = new EnrollmentException(format("Url:%s, Failed to enroll user %s ", url, user), e);
            logger.error(e.getMessage(), e);
            throw ee;
        }

    }

    /**
     * Re-Enroll the user with member service
     *
     * @param user User to be re-enrolled
     * @return enrollment
     * @throws EnrollmentException
     * @throws InvalidArgumentException
     */
    public Enrollment reenroll(User user) throws EnrollmentException, InvalidArgumentException {
        return reenroll(user, new EnrollmentRequest());
    }

    /**
     * Re-Enroll the user with member service
     *
     * @param user User to be re-enrolled
     * @param req  Enrollment request with the following fields: hosts, profile, csr, label
     * @return enrollment
     * @throws EnrollmentException
     * @throws InvalidArgumentException
     */

    public Enrollment reenroll(User user, EnrollmentRequest req) throws EnrollmentException, InvalidArgumentException {

        if (user == null) {
            throw new InvalidArgumentException("reenrollment user is missing");
        }
        if (user.getEnrollment() == null) {
            throw new InvalidArgumentException("reenrollment user is not a valid user object");
        }

        logger.debug(format("re-enroll user: %s, url: %s", user.getName(), url));

        try {
            setUpSSL();

            PublicKey publicKey = cryptoPrimitives.bytesToCertificate(user.getEnrollment().getCert()
                    .getBytes(StandardCharsets.UTF_8)).getPublicKey();

            KeyPair keypair = new KeyPair(publicKey, user.getEnrollment().getKey());

            // generate CSR
            PKCS10CertificationRequest csr = cryptoPrimitives.generateCertificationRequest(user.getName(), keypair);
            String pem = cryptoPrimitives.certificationRequestToPEM(csr);

            // build request body
            req.setCSR(pem);
            if (name != null && !name.isEmpty()) {
                req.setCAName(name);
            }
            String body = req.toJson();

            // build authentication header
            String authHdr = getHTTPAuthCertificate(user.getEnrollment(), body);
            JsonObject result = httpPost(url + HFCA_REENROLL, body, authHdr);

            // get new cert from response
            Base64.Decoder b64dec = Base64.getDecoder();
            String signedPem = new String(b64dec.decode(result.getString("Cert").getBytes(UTF_8)));
            logger.debug(format("[HFCAClient] re-enroll returned pem:[%s]", signedPem));

            logger.debug(format("reenroll user %s done.", user.getName()));
            return new HFCAEnrollment(keypair, signedPem);

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
     *
     * @param revoker    admin user who has revoker attribute configured in CA-server
     * @param enrollment the user enrollment to be revoked
     * @param reason     revoke reason, see RFC 5280
     * @throws RevocationException
     * @throws InvalidArgumentException
     */

    public void revoke(User revoker, Enrollment enrollment, String reason) throws RevocationException, InvalidArgumentException {

        if (enrollment == null) {
            throw new InvalidArgumentException("revokee enrollment is not set");
        }
        if (revoker == null) {
            throw new InvalidArgumentException("revoker is not set");
        }

        logger.debug(format("revoke revoker: %s, reason: %s, url: %s", revoker.getName(), reason, url));

        try {
            setUpSSL();

            // get cert from to-be-revoked enrollment
            BufferedInputStream pem = new BufferedInputStream(new ByteArrayInputStream(enrollment.getCert().getBytes()));
            CertificateFactory certFactory = CertificateFactory.getInstance(Config.getConfig().getCertificateFormat());
            X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(pem);

            // get its serial number
            String serial = DatatypeConverter.printHexBinary(certificate.getSerialNumber().toByteArray());

            // get its aki
            // 2.5.29.35 : AuthorityKeyIdentifier
            byte[] extensionValue = certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
            ASN1OctetString akiOc = ASN1OctetString.getInstance(extensionValue);
            String aki = DatatypeConverter.printHexBinary(AuthorityKeyIdentifier.getInstance(akiOc.getOctets()).getKeyIdentifier());

            // build request body
            RevocationRequest req = new RevocationRequest(name, null, serial, aki, reason);
            String body = req.toJson();

            String authHdr = getHTTPAuthCertificate(revoker.getEnrollment(), body);

            // send revoke request
            httpPost(url + HFCA_REVOKE, body, authHdr);
            logger.debug("revoke done");
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
     *
     * @param revoker admin user who has revoker attribute configured in CA-server
     * @param revokee user who is to be revoked
     * @param reason  revoke reason, see RFC 5280
     * @throws RevocationException
     * @throws InvalidArgumentException
     */

    public void revoke(User revoker, String revokee, String reason) throws RevocationException, InvalidArgumentException {

        logger.debug(format("revoke revoker: %s, revokee: %s, reason: %s", revoker, revokee, reason));

        if (Utils.isNullOrEmpty(revokee)) {
            throw new InvalidArgumentException("revokee user is not set");
        }
        if (revoker == null) {
            throw new InvalidArgumentException("revoker is not set");
        }

        try {
            setUpSSL();

            // build request body
            RevocationRequest req = new RevocationRequest(name, revokee, null, null, reason);
            String body = req.toJson();

            // build auth header
            String authHdr = getHTTPAuthCertificate(revoker.getEnrollment(), body);

            // send revoke request
            httpPost(url + HFCA_REVOKE, body, authHdr);
            logger.debug(format("revoke revokee: %s done.", revokee));
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
    String httpPost(String url, String body, UsernamePasswordCredentials credentials) throws Exception {
        logger.debug(format("httpPost %s, body:%s", url, body));
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
        logger.trace(format("httpPost %s  sending...", url));
        String responseBody = entity != null ? EntityUtils.toString(entity) : null;
        logger.trace(format("httpPost %s  responseBody %s", url, responseBody));

        if (status >= 400) {

            Exception e = new Exception(format("POST request to %s  with request body: %s, " +
                    "failed with status code: %d. Response: %s", url, body, status, responseBody));
            logger.error(e.getMessage());
            throw e;
        }
        logger.debug(format("httpPost Status: %d returning: %s ", status, responseBody));

        return responseBody;
    }

    JsonObject httpPost(String url, String body, String authHTTPCert) throws Exception {

        HttpPost httpPost = new HttpPost(url);
        logger.debug(format("httpPost %s, body:%s, authHTTPCert: %s", url, body, authHTTPCert));

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
        logger.trace(format("response status %d, HttpEntity %s ", status, "" + entity));
        String responseBody = entity != null ? EntityUtils.toString(entity) : null;
        logger.trace(format("responseBody: %s ", responseBody));

        if (status >= 400) {
            Exception e = new Exception(format("POST request to %s failed request body %s with status code: %d. Response: %s",
                    url, body, status, responseBody));
            logger.error(e.getMessage());
            throw e;
        }
        if (responseBody == null) {

            Exception e = new Exception(format("POST request to %s failed request body %s with null response body returned.", url, body));
            logger.error(e.getMessage());
            throw e;

        }
        logger.debug("Status: " + status);

        JsonReader reader = Json.createReader(new StringReader(responseBody));
        JsonObject jobj = (JsonObject) reader.read();
        boolean success = jobj.getBoolean("success");
        if (!success) {
            EnrollmentException e = new EnrollmentException(
                    format("POST request to %s failed request body %s Body of response did not contain success", url, body),
                    new Exception());
            logger.error(e.getMessage());
            throw e;
        }
        JsonObject result = jobj.getJsonObject("result");
        if (result == null) {
            EnrollmentException e = new EnrollmentException(format("POST request to %s failed request body %s " +
                    "Body of response did not contain result", url, body), new Exception());
            logger.error(e.getMessage());
            throw e;
        }
        JsonArray messages = jobj.getJsonArray("messages");
        if (messages != null && !messages.isEmpty()) {
            JsonObject jo = messages.getJsonObject(0);
            String message = format("POST request to %s failed request body %s response message [code %d]: %s",
                    url, body, jo.getInt("code"), jo.getString("message"));
            logger.info(message);
        }

        logger.debug(format("httpPost %s, body:%s result: %s", url, body, "" + result));
        return result;
    }

    private String getHTTPAuthCertificate(Enrollment enrollment, String body) throws Exception {
        Base64.Encoder b64 = Base64.getEncoder();
        String cert = b64.encodeToString(enrollment.getCert().getBytes(UTF_8));
        body = b64.encodeToString(body.getBytes(UTF_8));
        String signString = body + "." + cert;
        byte[] signature = cryptoPrimitives.sign(enrollment.getKey(), signString.getBytes(UTF_8));
        return cert + "." + b64.encodeToString(signature);
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
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
            };

            sslContext.init(null, new TrustManager[] {tm}, null);
        }

        @Override
        public Socket createSocket(Socket socket, String host, int port, boolean autoClose) throws IOException {
            return sslContext.getSocketFactory().createSocket(socket, host, port, autoClose);
        }

        @Override
        public Socket createSocket() throws IOException {
            return sslContext.getSocketFactory().createSocket();
        }
    }

}

