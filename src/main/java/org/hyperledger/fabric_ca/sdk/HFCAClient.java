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
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.MalformedURLException;
import java.net.Socket;
import java.net.URISyntaxException;
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
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.TimeZone;

import javax.json.Json;
import javax.json.JsonArray;
import javax.json.JsonObject;
import javax.json.JsonObjectBuilder;
import javax.json.JsonReader;
import javax.json.JsonValue;
import javax.json.JsonWriter;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import javax.xml.bind.DatatypeConverter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.ParseException;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.AuthCache;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpDelete;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.client.utils.URIBuilder;
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
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.NetworkConfig;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.helper.Utils;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric_ca.sdk.exception.AffiliationException;
import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.hyperledger.fabric_ca.sdk.exception.GenerateCRLException;
import org.hyperledger.fabric_ca.sdk.exception.HTTPException;
import org.hyperledger.fabric_ca.sdk.exception.IdentityException;
import org.hyperledger.fabric_ca.sdk.exception.InfoException;
import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric_ca.sdk.exception.RegistrationException;
import org.hyperledger.fabric_ca.sdk.exception.RevocationException;
import org.hyperledger.fabric_ca.sdk.helper.Config;

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;

/**
 * HFCAClient Hyperledger Fabric Certificate Authority Client.
 */

public class HFCAClient {
    /**
     * Default profile name.
     */
    public static final String DEFAULT_PROFILE_NAME = "";
    /**
     * HFCA_TYPE_PEER indicates that an identity is acting as a peer
     */
    public static final String HFCA_TYPE_PEER = "peer";
    /**
     * HFCA_TYPE_ORDERER indicates that an identity is acting as an orderer
     */
    public static final String HFCA_TYPE_ORDERER = "orderer";
    /**
     * HFCA_TYPE_CLIENT indicates that an identity is acting as a client
     */
    public static final String HFCA_TYPE_CLIENT = "client";
    /**
     * HFCA_TYPE_USER indicates that an identity is acting as a user
     */
    public static final String HFCA_TYPE_USER = "user";

    /**
     * HFCA_ATTRIBUTE_HFREGISTRARROLES is an attribute that allows a registrar to manage identities of the specified roles
     */
    public static final String HFCA_ATTRIBUTE_HFREGISTRARROLES = "hf.Registrar.Roles";
    /**
     * HFCA_ATTRIBUTE_HFREGISTRARDELEGATEROLES is an attribute that allows a registrar to give the roles specified
     * to a registree for its 'hf.Registrar.Roles' attribute
     */
    public static final String HFCA_ATTRIBUTE_HFREGISTRARDELEGATEROLES = "hf.Registrar.DelegateRoles";
    /**
     * HFCA_ATTRIBUTE_HFREGISTRARATTRIBUTES is an attribute that has a list of attributes that the registrar is allowed to register
     * for an identity
     */
    public static final String HFCA_ATTRIBUTE_HFREGISTRARATTRIBUTES = "hf.Registrar.Attributes";
    /**
     * HFCA_ATTRIBUTE_HFINTERMEDIATECA is a boolean attribute that allows an identity to enroll as an intermediate CA
     */
    public static final String HFCA_ATTRIBUTE_HFINTERMEDIATECA = "hf.IntermediateCA";
    /**
     * HFCA_ATTRIBUTE_HFREVOKER is a boolean attribute that allows an identity to revoker a user and/or certificates
     */
    public static final String HFCA_ATTRIBUTE_HFREVOKER = "hf.Revoker";
    /**
     * HFCA_ATTRIBUTE_HFAFFILIATIONMGR is a boolean attribute that allows an identity to manage affiliations
     */
    public static final String HFCA_ATTRIBUTE_HFAFFILIATIONMGR = "hf.AffiliationMgr";
    /**
     * HFCA_ATTRIBUTE_HFGENCRL is an attribute that allows an identity to generate a CRL
     */
    public static final String HFCA_ATTRIBUTE_HFGENCRL = "hf.GenCRL";

    private static final Config config = Config.getConfig();  // DO NOT REMOVE THIS IS NEEDED TO MAKE SURE WE FIRST LOAD CONFIG!!!

    private static final Log logger = LogFactory.getLog(HFCAClient.class);

    static final String FABRIC_CA_REQPROP = "caname";
    static final String HFCA_CONTEXT_ROOT = "/api/v1/";

    private static final String HFCA_ENROLL = HFCA_CONTEXT_ROOT + "enroll";
    private static final String HFCA_REGISTER = HFCA_CONTEXT_ROOT + "register";
    private static final String HFCA_REENROLL = HFCA_CONTEXT_ROOT + "reenroll";
    private static final String HFCA_REVOKE = HFCA_CONTEXT_ROOT + "revoke";
    private static final String HFCA_INFO = HFCA_CONTEXT_ROOT + "cainfo";
    private static final String HFCA_GENCRL = HFCA_CONTEXT_ROOT + "gencrl";

    private final String url;
    private final boolean isSSL;
    private final Properties properties;

    /**
     * The Certificate Authority name.
     *
     * @return May return null or empty string for default certificate authority.
     */
    public String getCAName() {
        return caName;
    }

    private final String caName;

    private CryptoSuite cryptoSuite;

    private int statusCode = 400;

    /**
     * The Status Code level of client, HTTP status codes above this value will return in a
     * exception, otherwise, the status code will be return the status code and appropriate error
     * will be logged.
     *
     * @return statusCode
     */
    public int getStatusCode() {
        return statusCode;
    }

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
    HFCAClient(String caName, String url, Properties properties) throws MalformedURLException {
        logger.debug(format("new HFCAClient %s", url));
        this.url = url;

        this.caName = caName; //name may be null

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

    /**
     * Create HFCAClient from a NetworkConfig.CAInfo using default crypto suite.
     *
     * @param caInfo created from NetworkConfig.getOrganizationInfo("org_name").getCertificateAuthorities()
     * @return HFCAClient
     * @throws MalformedURLException
     * @throws InvalidArgumentException
     */

    public static HFCAClient createNewInstance(NetworkConfig.CAInfo caInfo) throws MalformedURLException, InvalidArgumentException {

        try {
            return createNewInstance(caInfo, CryptoSuite.Factory.getCryptoSuite());
        } catch (MalformedURLException e) {
            throw e;
        } catch (Exception e) {
            throw new InvalidArgumentException(e);
        }
    }

    /**
     * Create HFCAClient from a NetworkConfig.CAInfo
     *
     * @param caInfo      created from NetworkConfig.getOrganizationInfo("org_name").getCertificateAuthorities()
     * @param cryptoSuite the specific cryptosuite to use.
     * @return HFCAClient
     * @throws MalformedURLException
     * @throws InvalidArgumentException
     */

    public static HFCAClient createNewInstance(NetworkConfig.CAInfo caInfo, CryptoSuite cryptoSuite) throws MalformedURLException, InvalidArgumentException {

        if (null == caInfo) {
            throw new InvalidArgumentException("The caInfo parameter can not be null.");
        }

        if (null == cryptoSuite) {
            throw new InvalidArgumentException("The cryptoSuite parameter can not be null.");
        }

        HFCAClient ret = new HFCAClient(caInfo.getCAName(), caInfo.getUrl(), caInfo.getProperties());
        ret.setCryptoSuite(cryptoSuite);
        return ret;
    }

    public void setCryptoSuite(CryptoSuite cryptoSuite) {
        this.cryptoSuite = cryptoSuite;
    }

    public CryptoSuite getCryptoSuite() {
        return cryptoSuite;
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

        if (cryptoSuite == null) {
            throw new InvalidArgumentException("Crypto primitives not set.");
        }

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
            JsonObject resp = httpPost(url + HFCA_REGISTER, body, registrar);
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

        if (cryptoSuite == null) {
            throw new InvalidArgumentException("Crypto primitives not set.");
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
                keypair = cryptoSuite.keyGen();

                logger.debug("[HFCAClient.enroll] Generating keys...done!");
            }

            if (pem == null) {
                String csr = cryptoSuite.generateCertificationRequest(user, keypair);
                req.setCSR(csr);
            }

            if (caName != null && !caName.isEmpty()) {
                req.setCAName(caName);
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
     * Return information on the Fabric Certificate Authority.
     * No credentials are needed for this API.
     *
     * @return {@link HFCAInfo}
     * @throws InfoException
     * @throws InvalidArgumentException
     */

    public HFCAInfo info() throws InfoException, InvalidArgumentException {

        logger.debug(format("info url:%s", url));
        if (cryptoSuite == null) {
            throw new InvalidArgumentException("Crypto primitives not set.");
        }

        setUpSSL();

        try {

            JsonObjectBuilder factory = Json.createObjectBuilder();

            if (caName != null) {
                factory.add(HFCAClient.FABRIC_CA_REQPROP, caName);
            }
            JsonObject body = factory.build();

            String responseBody = httpPost(url + HFCA_INFO, body.toString(),
                    (UsernamePasswordCredentials) null);

            logger.debug("response:" + responseBody);

            JsonReader reader = Json.createReader(new StringReader(responseBody));
            JsonObject jsonst = (JsonObject) reader.read();

            boolean success = jsonst.getBoolean("success");
            logger.debug(format("[HFCAClient] enroll success:[%s]", success));

            if (!success) {
                throw new EnrollmentException(format("FabricCA failed info %s", url));
            }

            JsonObject result = jsonst.getJsonObject("result");
            if (result == null) {
                throw new InfoException(format("FabricCA info error  - response did not contain a result url %s", url));
            }

            String caName = result.getString("CAName");
            String caChain = result.getString("CAChain");
            String version = null;
            if (result.containsKey("Version")) {
                version = result.getString("Version");
            }

            return new HFCAInfo(caName, caChain, version);

        } catch (Exception e) {
            InfoException ee = new InfoException(format("Url:%s, Failed to get info", url), e);
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

        if (cryptoSuite == null) {
            throw new InvalidArgumentException("Crypto primitives not set.");
        }

        if (user == null) {
            throw new InvalidArgumentException("reenrollment user is missing");
        }
        if (user.getEnrollment() == null) {
            throw new InvalidArgumentException("reenrollment user is not a valid user object");
        }

        logger.debug(format("re-enroll user: %s, url: %s", user.getName(), url));

        try {
            setUpSSL();

            PublicKey publicKey = cryptoSuite.bytesToCertificate(user.getEnrollment().getCert()
                    .getBytes(StandardCharsets.UTF_8)).getPublicKey();

            KeyPair keypair = new KeyPair(publicKey, user.getEnrollment().getKey());

            // generate CSR

            String pem = cryptoSuite.generateCertificationRequest(user.getName(), keypair);

            // build request body
            req.setCSR(pem);
            if (caName != null && !caName.isEmpty()) {
                req.setCAName(caName);
            }
            String body = req.toJson();

            // build authentication header
            JsonObject result = httpPost(url + HFCA_REENROLL, body, user);

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
        revokeInternal(revoker, enrollment, reason, false);
    }

    /**
     * revoke one enrollment of user
     *
     * @param revoker    admin user who has revoker attribute configured in CA-server
     * @param enrollment the user enrollment to be revoked
     * @param reason     revoke reason, see RFC 5280
     * @param genCRL     generate CRL list
     * @throws RevocationException
     * @throws InvalidArgumentException
     */

    public String revoke(User revoker, Enrollment enrollment, String reason, boolean genCRL) throws RevocationException, InvalidArgumentException {
        return revokeInternal(revoker, enrollment, reason, genCRL);
    }

    private String revokeInternal(User revoker, Enrollment enrollment, String reason, boolean genCRL) throws RevocationException, InvalidArgumentException {

        if (cryptoSuite == null) {
            throw new InvalidArgumentException("Crypto primitives not set.");
        }

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
            RevocationRequest req = new RevocationRequest(caName, null, serial, aki, reason, genCRL);
            String body = req.toJson();

            // send revoke request
            JsonObject resp = httpPost(url + HFCA_REVOKE, body, revoker);
            logger.debug("revoke done");

            if (genCRL) {
                if (resp.isEmpty()) {
                    throw new RevocationException("Failed to return CRL, revoke response is empty");
                }
                if (resp.isNull("CRL")) {
                    throw new RevocationException("Failed to return CRL");
                }
                return resp.getString("CRL");
            }
            return null;
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
        revokeInternal(revoker, revokee, reason, false);
    }

    /**
     * revoke one user (including his all enrollments)
     *
     * @param revoker admin user who has revoker attribute configured in CA-server
     * @param revokee user who is to be revoked
     * @param reason  revoke reason, see RFC 5280
     * @param genCRL  generate CRL
     * @throws RevocationException
     * @throws InvalidArgumentException
     */

    public String revoke(User revoker, String revokee, String reason, boolean genCRL) throws RevocationException, InvalidArgumentException {
        return revokeInternal(revoker, revokee, reason, genCRL);
    }

    private String revokeInternal(User revoker, String revokee, String reason, boolean genCRL) throws RevocationException, InvalidArgumentException {

        if (cryptoSuite == null) {
            throw new InvalidArgumentException("Crypto primitives not set.");
        }

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
            RevocationRequest req = new RevocationRequest(caName, revokee, null, null, reason, genCRL);
            String body = req.toJson();

            // send revoke request
            JsonObject resp = httpPost(url + HFCA_REVOKE, body, revoker);

            logger.debug(format("revoke revokee: %s done.", revokee));

            if (genCRL) {
                if (resp.isEmpty()) {
                    throw new RevocationException("Failed to return CRL, revoke response is empty");
                }
                if (resp.isNull("CRL")) {
                    throw new RevocationException("Failed to return CRL");
                }
                return resp.getString("CRL");
            }
            return null;
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw new RevocationException("Error while revoking the user. " + e.getMessage(), e);
        }
    }

    /**
     * revoke one certificate
     *
     * @param revoker admin user who has revoker attribute configured in CA-server
     * @param serial  serial number of the certificate to be revoked
     * @param aki     aki of the certificate to be revoke
     * @param reason  revoke reason, see RFC 5280
     * @throws RevocationException
     * @throws InvalidArgumentException
     */

    public void revoke(User revoker, String serial, String aki, String reason) throws RevocationException, InvalidArgumentException {
        revokeInternal(revoker, serial, aki, reason, false);
    }

    /**
     * revoke one enrollment of user
     *
     * @param revoker admin user who has revoker attribute configured in CA-server
     * @param serial  serial number of the certificate to be revoked
     * @param aki     aki of the certificate to be revoke
     * @param reason  revoke reason, see RFC 5280
     * @param genCRL  generate CRL list
     * @throws RevocationException
     * @throws InvalidArgumentException
     */

    public String revoke(User revoker, String serial, String aki, String reason, boolean genCRL) throws RevocationException, InvalidArgumentException {
        return revokeInternal(revoker, serial, aki, reason, genCRL);
    }

    private String revokeInternal(User revoker, String serial, String aki, String reason, boolean genCRL) throws RevocationException, InvalidArgumentException {

        if (cryptoSuite == null) {
            throw new InvalidArgumentException("Crypto primitives not set.");
        }

        if (Utils.isNullOrEmpty(serial)) {
            throw new IllegalArgumentException("Serial number id required to revoke ceritificate");
        }
        if (Utils.isNullOrEmpty(aki)) {
            throw new IllegalArgumentException("AKI is required to revoke certificate");
        }
        if (revoker == null) {
            throw new InvalidArgumentException("revoker is not set");
        }

        logger.debug(format("revoke revoker: %s, reason: %s, url: %s", revoker.getName(), reason, url));

        try {
            setUpSSL();

            // build request body
            RevocationRequest req = new RevocationRequest(caName, null, serial, aki, reason, genCRL);
            String body = req.toJson();

            // send revoke request
            JsonObject resp = httpPost(url + HFCA_REVOKE, body, revoker);
            logger.debug("revoke done");

            if (genCRL) {
                if (resp.isEmpty()) {
                    throw new RevocationException("Failed to return CRL, revoke response is empty");
                }
                if (resp.isNull("CRL")) {
                    throw new RevocationException("Failed to return CRL");
                }
                return resp.getString("CRL");
            }
            return null;
        } catch (CertificateException e) {
            logger.error("Cannot validate certificate. Error is: " + e.getMessage());
            throw new RevocationException("Error while revoking cert. " + e.getMessage(), e);
        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw new RevocationException("Error while revoking the user. " + e.getMessage(), e);
        }
    }

    /**
     * Generate certificate revocation list.
     *
     * @param registrar     admin user configured in CA-server
     * @param revokedBefore Restrict certificates returned to revoked before this date if not null.
     * @param revokedAfter  Restrict certificates returned to revoked after this date if not null.
     * @param expireBefore  Restrict certificates returned to expired before this date if not null.
     * @param expireAfter   Restrict certificates returned to expired after this date if not null.
     * @throws InvalidArgumentException
     */

    public String generateCRL(User registrar, Date revokedBefore, Date revokedAfter, Date expireBefore, Date expireAfter)
            throws InvalidArgumentException, GenerateCRLException {

        if (cryptoSuite == null) {
            throw new InvalidArgumentException("Crypto primitives not set.");
        }

        if (registrar == null) {
            throw new InvalidArgumentException("registrar is not set");
        }

        try {
            setUpSSL();

            //---------------------------------------
            JsonObjectBuilder factory = Json.createObjectBuilder();
            if (revokedBefore != null) {
                factory.add("revokedBefore", toJson(revokedBefore));
            }
            if (revokedAfter != null) {
                factory.add("revokedAfter", toJson(revokedAfter));
            }
            if (expireBefore != null) {
                factory.add("expireBefore", toJson(expireBefore));
            }
            if (expireAfter != null) {
                factory.add("expireAfter", toJson(expireAfter));
            }
            if (caName != null) {
                factory.add(HFCAClient.FABRIC_CA_REQPROP, caName);
            }

            JsonObject jsonObject = factory.build();

            StringWriter stringWriter = new StringWriter();
            JsonWriter jsonWriter = Json.createWriter(new PrintWriter(stringWriter));
            jsonWriter.writeObject(jsonObject);
            jsonWriter.close();
            String body = stringWriter.toString();

            //---------------------------------------

            // send revoke request
            JsonObject ret = httpPost(url + HFCA_GENCRL, body, registrar);

            return ret.getString("CRL");

        } catch (Exception e) {
            logger.error(e.getMessage(), e);
            throw new GenerateCRLException(e.getMessage(), e);
        }
    }

    /**
     * Creates a new HFCA Identity object
     *
     * @param enrollmentID The enrollment ID associated for this identity
     * @return HFCAIdentity object
     * @throws InvalidArgumentException Invalid (null) argument specified
     */

    public HFCAIdentity newHFCAIdentity(String enrollmentID) throws InvalidArgumentException {
        return new HFCAIdentity(enrollmentID, this);
    }

    /**
     * gets all identities that the registrar is allowed to see
     *
     * @param registrar The identity of the registrar (i.e. who is performing the registration).
     * @return the identity that was requested
     * @throws IdentityException        if adding an identity fails.
     * @throws InvalidArgumentException Invalid (null) argument specified
     */

    public Collection<HFCAIdentity> getHFCAIdentities(User registrar) throws IdentityException, InvalidArgumentException {
        if (registrar == null) {
            throw new InvalidArgumentException("Registrar should be a valid member");
        }

        logger.debug(format("identity  url: %s, registrar: %s", url, registrar.getName()));

        try {
            JsonObject result = httpGet(HFCAIdentity.HFCA_IDENTITY, registrar);

            Collection<HFCAIdentity> allIdentities = new ArrayList<HFCAIdentity>();

            JsonArray identities = result.getJsonArray("identities");
            if (identities != null && !identities.isEmpty()) {
                for (int i = 0; i < identities.size(); i++) {
                    JsonObject identity = identities.getJsonObject(i);
                    HFCAIdentity idObj = new HFCAIdentity(identity);
                    allIdentities.add(idObj);
                }
            }

            logger.debug(format("identity  url: %s, registrar: %s done.", url, registrar));
            return allIdentities;
        } catch (HTTPException e) {
            String msg = format("[HTTP Status Code: %d] - Error while getting all users from url '%s': %s", e.getStatusCode(), url, e.getMessage());
            IdentityException identityException = new IdentityException(msg, e);
            logger.error(msg);
            throw identityException;
        } catch (Exception e) {
            String msg = format("Error while getting all users from url '%s': %s", url, e.getMessage());
            IdentityException identityException = new IdentityException(msg, e);
            logger.error(msg);
            throw identityException;
        }

    }

    /**
     * @param name Name of the affiliation
     * @return HFCAAffiliation object
     * @throws InvalidArgumentException Invalid (null) argument specified
     */
    public HFCAAffiliation newHFCAAffiliation(String name) throws InvalidArgumentException {
        return new HFCAAffiliation(name, this);
    }

    /**
     * gets all affiliations that the registrar is allowed to see
     *
     * @param registrar The identity of the registrar (i.e. who is performing the registration).
     * @return The affiliations that were requested
     * @throws AffiliationException     if getting all affiliations fails
     * @throws InvalidArgumentException
     */

    public HFCAAffiliation getHFCAAffiliations(User registrar) throws AffiliationException, InvalidArgumentException {
        if (cryptoSuite == null) {
            throw new InvalidArgumentException("Crypto primitives not set.");
        }

        if (registrar == null) {
            throw new InvalidArgumentException("Registrar should be a valid member");
        }

        logger.debug(format("affiliations  url: %s, registrar: %s", url, registrar.getName()));

        try {
            JsonObject result = httpGet(HFCAAffiliation.HFCA_AFFILIATION, registrar);
            HFCAAffiliation affiliations = new HFCAAffiliation(result);

            logger.debug(format("affiliations  url: %s, registrar: %s done.", url, registrar));
            return affiliations;
        } catch (HTTPException e) {
            String msg = format("[HTTP Status Code: %d] - Error while getting all affiliations from url '%s': %s", e.getStatusCode(), url, e.getMessage());
            AffiliationException affiliationException = new AffiliationException(msg, e);
            logger.error(msg);
            throw affiliationException;
        } catch (Exception e) {
            String msg = format("Error while getting all affiliations from url '%s': %s", url, e.getMessage());
            AffiliationException affiliationException = new AffiliationException(msg, e);
            logger.error(msg);
            throw affiliationException;
        }

    }

    private String toJson(Date date) {
        final TimeZone utc = TimeZone.getTimeZone("UTC");

        SimpleDateFormat tformat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSXXX");
        tformat.setTimeZone(utc);
        return tformat.format(date);
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

        final HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
        CredentialsProvider provider = null;
        if (credentials != null) {
            provider = new BasicCredentialsProvider();

            provider.setCredentials(AuthScope.ANY, credentials);
            httpClientBuilder.setDefaultCredentialsProvider(provider);
        }

        if (registry != null) {

            httpClientBuilder.setConnectionManager(new PoolingHttpClientConnectionManager(registry));

        }

        HttpClient client = httpClientBuilder.build();

        HttpPost httpPost = new HttpPost(url);

        AuthCache authCache = new BasicAuthCache();

        HttpHost targetHost = new HttpHost(httpPost.getURI().getHost(), httpPost.getURI().getPort());

        if (credentials != null) {
            authCache.put(targetHost, new

                    BasicScheme());

        }

        final HttpClientContext context = HttpClientContext.create();

        if (null != provider) {
            context.setCredentialsProvider(provider);
        }

        if (credentials != null) {
            context.setAuthCache(authCache);
        }

        httpPost.setEntity(new StringEntity(body));
        if (credentials != null) {
            httpPost.addHeader(new

                    BasicScheme().

                    authenticate(credentials, httpPost, context));
        }

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

    JsonObject httpPost(String url, String body, User registrar) throws Exception {
        String authHTTPCert = getHTTPAuthCertificate(registrar.getEnrollment(), body);
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

        return getResult(response, body, "POST");
    }

    JsonObject httpGet(String url, User registrar) throws Exception {
        String authHTTPCert = getHTTPAuthCertificate(registrar.getEnrollment(), "");
        url = getURL(url);
        HttpGet httpGet = new HttpGet(url);
        logger.debug(format("httpGet %s, authHTTPCert: %s", url, authHTTPCert));

        final HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
        if (registry != null) {
            httpClientBuilder.setConnectionManager(new PoolingHttpClientConnectionManager(registry));
        }
        HttpClient client = httpClientBuilder.build();

        final HttpClientContext context = HttpClientContext.create();
        httpGet.addHeader("Authorization", authHTTPCert);

        HttpResponse response = client.execute(httpGet, context);

        return getResult(response, "", "GET");
    }

    JsonObject httpPut(String url, String body, User registrar) throws Exception {
        String authHTTPCert = getHTTPAuthCertificate(registrar.getEnrollment(), body);
        HttpPut httpPut = new HttpPut(url);
        logger.debug(format("httpPutt %s, body:%s, authHTTPCert: %s", url, body, authHTTPCert));

        final HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
        if (registry != null) {
            httpClientBuilder.setConnectionManager(new PoolingHttpClientConnectionManager(registry));
        }
        HttpClient client = httpClientBuilder.build();

        final HttpClientContext context = HttpClientContext.create();
        httpPut.setEntity(new StringEntity(body));
        httpPut.addHeader("Authorization", authHTTPCert);

        HttpResponse response = client.execute(httpPut, context);

        return getResult(response, body, "PUT");
    }

    JsonObject httpDelete(String url, User registrar) throws Exception {
        String authHTTPCert = getHTTPAuthCertificate(registrar.getEnrollment(), "");
        HttpDelete httpDelete = new HttpDelete(url);
        logger.debug(format("httpPut %s, authHTTPCert: %s", url, authHTTPCert));

        final HttpClientBuilder httpClientBuilder = HttpClientBuilder.create();
        if (registry != null) {
            httpClientBuilder.setConnectionManager(new PoolingHttpClientConnectionManager(registry));
        }
        HttpClient client = httpClientBuilder.build();

        final HttpClientContext context = HttpClientContext.create();
        httpDelete.addHeader("Authorization", authHTTPCert);

        HttpResponse response = client.execute(httpDelete, context);

        return getResult(response, "", "DELETE");
    }

    JsonObject getResult(HttpResponse response, String body, String type) throws HTTPException, ParseException, IOException {

        int respStatusCode = response.getStatusLine().getStatusCode();
        HttpEntity entity = response.getEntity();
        logger.trace(format("response status %d, HttpEntity %s ", respStatusCode, "" + entity));
        String responseBody = entity != null ? EntityUtils.toString(entity) : null;
        logger.trace(format("responseBody: %s ", responseBody));

        // If the status code in the response is greater or equal to the status code set in the client object then an exception will
        // be thrown, otherwise, we continue to read the response and return any error code that is less than 'statusCode'
        if (respStatusCode >= statusCode) {
            HTTPException e = new HTTPException(format("%s request to %s failed request body %s. Response: %s",
                    type, url, body, responseBody), respStatusCode);
            logger.error(e.getMessage());
            throw e;
        }
        if (responseBody == null) {

            HTTPException e = new HTTPException(format("%s request to %s failed request body %s with null response body returned.", type, url, body), respStatusCode);
            logger.error(e.getMessage());
            throw e;

        }

        logger.debug("Status: " + respStatusCode);

        JsonReader reader = Json.createReader(new StringReader(responseBody));
        JsonObject jobj = (JsonObject) reader.read();

        JsonObjectBuilder job = Json.createObjectBuilder();
        job.add("statusCode", respStatusCode);

        JsonArray errors = jobj.getJsonArray("errors");
        // If the status code is greater than or equal to 400 but less than or equal to the client status code setting,
        // then encountered an error and we return back the status code, and log the error rather than throwing an exception.
        if (respStatusCode < statusCode && respStatusCode >= 400) {
            if (errors != null && !errors.isEmpty()) {
                JsonObject jo = errors.getJsonObject(0);
                String errorMsg = format("[HTTP Status Code: %d] - %s request to %s failed request body %s error message: [Error Code %d] - %s",
                        respStatusCode, type, url, body, jo.getInt("code"), jo.getString("message"));
                logger.error(errorMsg);
            }
            JsonObject result = job.build();
            return result;
        }
        if (errors != null && !errors.isEmpty()) {
            JsonObject jo = errors.getJsonObject(0);
            HTTPException e = new HTTPException(format("%s request to %s failed request body %s error message: [Error Code %d] - %s",
                    type, url, body, jo.getInt("code"), jo.getString("message")), respStatusCode);
            throw e;
        }

        boolean success = jobj.getBoolean("success");
        if (!success) {
            HTTPException e = new HTTPException(
                    format("%s request to %s failed request body %s Body of response did not contain success", type, url, body), respStatusCode);
            logger.error(e.getMessage());
            throw e;
        }

        JsonObject result = jobj.getJsonObject("result");
        if (result == null) {
            HTTPException e = new HTTPException(format("%s request to %s failed request body %s " +
                    "Body of response did not contain result", type, url, body), respStatusCode);
            logger.error(e.getMessage());
            throw e;
        }

        JsonArray messages = jobj.getJsonArray("messages");
        if (messages != null && !messages.isEmpty()) {
            JsonObject jo = messages.getJsonObject(0);
            String message = format("%s request to %s failed request body %s response message: [Error Code %d] - %s",
                    type, url, body, jo.getInt("code"), jo.getString("message"));
            logger.info(message);
        }

        // Construct JSON object that contains the result and HTTP status code
        for (Entry<String, JsonValue> entry : result.entrySet()) {
            job.add(entry.getKey(), entry.getValue());
        }
        job.add("statusCode", respStatusCode);
        result = job.build();

        logger.debug(format("%s %s, body:%s result: %s", type, url, body, "" + result));
        return result;
    }

    String getHTTPAuthCertificate(Enrollment enrollment, String body) throws Exception {
        Base64.Encoder b64 = Base64.getEncoder();
        String cert = b64.encodeToString(enrollment.getCert().getBytes(UTF_8));
        body = b64.encodeToString(body.getBytes(UTF_8));
        String signString = body + "." + cert;
        byte[] signature = cryptoSuite.sign(enrollment.getKey(), signString.getBytes(UTF_8));
        return cert + "." + b64.encodeToString(signature);
    }

    private Registry<ConnectionSocketFactory> registry = null;
    //Only use crypto primitives for reuse of its truststore on TLS
    CryptoPrimitives cryptoPrimitives = null;

    private void setUpSSL() throws InvalidArgumentException {

        if (cryptoPrimitives == null) {
            try {
                cryptoPrimitives = new CryptoPrimitives();
                cryptoPrimitives.init();
            } catch (Exception e) {
                throw new InvalidArgumentException(e);
            }
        }

        if (isSSL && null == registry) {
            if (properties.containsKey("pemBytes") && properties.containsKey("pemFile")) {

                throw new InvalidArgumentException("Properties can not have both \"pemBytes\" and \"pemFile\" specified. ");

            }
            try {

                if (properties.containsKey("pemBytes")) {
                    byte[] pemBytes = (byte[]) properties.get("pemBytes");

                    cryptoPrimitives.addCACertificateToTrustStore(pemBytes, pemBytes.toString());

                } else {
                    String pemFile = properties.getProperty("pemFile");
                    if (pemFile != null) {

                        cryptoPrimitives.addCACertificateToTrustStore(new File(pemFile), pemFile);

                    }

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

    String getURL(String endpoint) throws URISyntaxException, MalformedURLException, InvalidArgumentException {
        setUpSSL();
        String url = this.url + endpoint;
        URIBuilder uri = new URIBuilder(url);
        if (caName != null) {
            uri.addParameter("ca", caName);
        }
        return uri.build().toURL().toString();
    }

    String getURL(String endpoint, Map<String, String> queryMap) throws URISyntaxException, MalformedURLException, InvalidArgumentException {
        setUpSSL();
        String url = this.url + endpoint;
        URIBuilder uri = new URIBuilder(url);
        if (caName != null) {
            uri.addParameter("ca", caName);
        }
        if (queryMap != null) {
            for (Map.Entry<String, String> param : queryMap.entrySet()) {
                uri.addParameter(param.getKey(), param.getValue());
            }
        }
        return uri.build().toURL().toString();
    }

    // Convert the identity request to a JSON string
    String toJson(JsonObject toJsonFunc) {
        StringWriter stringWriter = new StringWriter();
        JsonWriter jsonWriter = Json.createWriter(new PrintWriter(stringWriter));
        jsonWriter.writeObject(toJsonFunc);
        jsonWriter.close();
        return stringWriter.toString();
    }
}

