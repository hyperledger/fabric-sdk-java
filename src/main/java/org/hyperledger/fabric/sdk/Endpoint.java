/*
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import static java.lang.String.format;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.hyperledger.fabric.sdk.NetworkConfig.CLIENT_CERT_BYTES;
import static org.hyperledger.fabric.sdk.NetworkConfig.CLIENT_CERT_FILE;
import static org.hyperledger.fabric.sdk.NetworkConfig.CLIENT_KEY_BYTES;
import static org.hyperledger.fabric.sdk.NetworkConfig.CLIENT_KEY_FILE;
import static org.hyperledger.fabric.sdk.helper.Utils.parseGrpcUrl;

import com.google.common.collect.ImmutableMap.Builder;
import io.grpc.ClientInterceptor;
import io.grpc.ManagedChannelBuilder;
import io.grpc.netty.shaded.io.grpc.netty.GrpcSslContexts;
import io.grpc.netty.shaded.io.grpc.netty.NegotiationType;
import io.grpc.netty.shaded.io.grpc.netty.NettyChannelBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContext;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslContextBuilder;
import io.grpc.netty.shaded.io.netty.handler.ssl.SslProvider;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.instrumentation.grpc.v1_6.GrpcTelemetry;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Optional;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.math3.util.Pair;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.helper.Utils;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;

class Endpoint {

    private static final Log logger = LogFactory.getLog(Endpoint.class);

    private static final String SSL_PROVIDER = Config.getConfig().getDefaultSSLProvider();
    private static final String SSL_NEGOTIATION = Config.getConfig().getDefaultSSLNegotiationType();
    private static final OpenTelemetry OPEN_TELEMETRY = Config.getConfig().getOpenTelemetry();
    private static final GrpcTelemetry GRPC_TELEMETRY = GrpcTelemetry.create(OPEN_TELEMETRY);

    private static final Pattern PEMFILE_SPLIT_PATTERN = Pattern.compile("[ \t]*,[ \t]*");
    private static final Pattern CERT_BODY_PATTERN = Pattern.compile("-+[ \t]*(BEGIN|END)[ \t]+CERTIFICATE[ \t]*-+");
    private static final Pattern WHITESPACE_PATTERN = Pattern.compile("\\s");

    public static final String PROPERTY_PROTOCOL = "protocol";
    public static final String PROPERTY_PORT = "port";
    public static final String PROPERTY_HOST = "host";
    public static final String PROPERTY_HOSTNAME_OVERRIDE = "hostnameOverride";
    public static final String PROPERTY_TRUST_SERVER_CERTIFICATE = "trustServerCertificate";
    public static final String PROPERTY_SSL_PROVIDER = "sslProvider";
    public static final String PROPERTY_NEGOTIATION_TYPE = "negotiationType";
    public static final String PROPERTY_PEM_FILE = "pemFile";
    public static final String PROPERTY_PEM_BYTES = "pemBytes";

    private final String addr;
    private final int port;
    private final String url;
    private byte[] clientTLSCertificateDigest;
    private byte[] tlsClientCertificatePEMBytes;
    private final NettyChannelBuilder channelBuilder;

    private static final Map<String, String> CN_CACHE = Collections.synchronizedMap(new HashMap<>());

    Endpoint(String url, Properties properties) {
        logger.trace(format("Creating endpoint for url %s", url));
        this.url = url;
        Properties purl = parseGrpcUrl(url);
        String protocol = purl.getProperty(PROPERTY_PROTOCOL).toLowerCase(Locale.ROOT);
        addr = purl.getProperty(PROPERTY_HOST);
        port = Integer.parseInt(purl.getProperty(PROPERTY_PORT));

        try {
            switch (protocol) {
                case "grpc":
                    channelBuilder = createChannelBuilder(properties)
                                         .negotiationType(NegotiationType.PLAINTEXT);
                    break;
                case "grpcs":
                    channelBuilder = createGrpcsChannelBuilder(url, properties);
                    break;
                default:
                    throw new RuntimeException("invalid protocol: " + protocol);
            }
        } catch (RuntimeException e) {
            logger.error(format("Endpoint %s, exception '%s'", url, e.getMessage()), e);
            throw e;
        } catch (IllegalAccessException | NoSuchMethodException | InvocationTargetException e) {
            logger.error(format("Endpoint %s, exception '%s'", url, e.getMessage()), e);
            logger.error(e);
            throw new RuntimeException(e);
        }
    }

    private NettyChannelBuilder createChannelBuilder(Properties properties)
        throws InvocationTargetException, IllegalAccessException, NoSuchMethodException {

        ClientInterceptor clientInterceptor = GRPC_TELEMETRY.newClientInterceptor();

        final NettyChannelBuilder channelBuilder = NettyChannelBuilder.forAddress(addr, port)
                                                       .intercept(clientInterceptor);
        addNettyBuilderProps(channelBuilder, properties);
        return channelBuilder;
    }

    private NettyChannelBuilder createGrpcsChannelBuilder(String url, Properties properties)
        throws InvocationTargetException, IllegalAccessException, NoSuchMethodException {

        Pair<PrivateKey, X509Certificate[]> clientTLSProps = readClientTLSProps(url, properties);

        PrivateKey clientKey = clientTLSProps.getKey();
        X509Certificate[] clientCert = clientTLSProps.getValue();

        GrpcsContext grpcsContext = readGrpcsProps(url, properties);
        Optional<byte[]> pemBytesOpt = grpcsContext.getPemBytes();
        Optional<String> cnOpt = grpcsContext.getCn();

        String sslp = readSslProviderProperty(url, properties);
        String nt = readNegotionTypeProperty(url, properties);

        if (!pemBytesOpt.isPresent()) {
            // use root certificate
            return createChannelBuilder(properties);
        }

        byte[] pemBytes = pemBytesOpt.get();

        logger.trace(format("Endpoint %s Negotiation type: '%s', SSLprovider: '%s'",
            url, nt, sslp
        ));
        SslProvider sslprovider = sslp.equals("openSSL") ? SslProvider.OPENSSL : SslProvider.JDK;
        NegotiationType ntype = nt.equals("TLS") ? NegotiationType.TLS : NegotiationType.PLAINTEXT;

        SslContextBuilder clientContextBuilder = getSslContextBuilder(clientCert, clientKey, sslprovider);

        logger.trace(
            format("Endpoint %s  final server pemBytes: %s",
                url, Hex.encodeHexString(pemBytes)
            )
        );

        SslContext sslContext;
        try (InputStream myInputStream = new ByteArrayInputStream(pemBytes)) {
            sslContext = clientContextBuilder
                             .trustManager(myInputStream)
                             .build();
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }

        NettyChannelBuilder channelBuilder = createChannelBuilder(properties)
                                                       .sslContext(sslContext)
                                                       .negotiationType(ntype);

        if (cnOpt.isPresent()) {
            String cn = cnOpt.get();
            logger.debug(format("Endpoint %s, using CN overrideAuthority: '%s'", url, cn));
            channelBuilder.overrideAuthority(cn);
        }
        return channelBuilder;

    }

    private static GrpcsContext readGrpcsProps(String url, Properties properties) {
        if (properties == null) {
            return new GrpcsContext(null, null);
        }

        CryptoPrimitives cp;
        try {
            cp = new CryptoPrimitives();
        } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
            throw new RuntimeException(e);
        }

        Optional<byte[]> pemBytesOpt = getPEMFile(url, properties);

        String cn = null;
        if (!pemBytesOpt.isPresent()) {
            logger.warn(format("Endpoint %s is grpcs with no CA certificates", url));
        } else {
            try {
                final byte[] pemBytes = pemBytesOpt.get();
                cn = properties.getProperty(PROPERTY_HOSTNAME_OVERRIDE);
                if (cn == null && "true".equals(properties.getProperty(PROPERTY_TRUST_SERVER_CERTIFICATE))) {
                    final String cnKey = new String(pemBytes, UTF_8);
                    cn = CN_CACHE.get(cnKey);
                    if (cn == null) {
                        X500Name x500name = new JcaX509CertificateHolder(
                            (X509Certificate) cp.bytesToCertificate(pemBytes)).getSubject();
                        RDN rdn = x500name.getRDNs(BCStyle.CN)[0];
                        cn = IETFUtils.valueToString(rdn.getFirst().getValue());
                        CN_CACHE.put(cnKey, cn);
                    }
                }
            } catch (CertificateEncodingException | CryptoException e) {
                /// Mostly a development env. just log it.
                logger.error(
                    format(
                        "Error getting Subject CN from certificate. "
                            + "Try setting it specifically with hostnameOverride property. %s", e.getMessage()
                    )
                );
            }
        }

        return new GrpcsContext(cn, pemBytesOpt.orElse(null));
    }

    private static String readNegotionTypeProperty(String url, Properties properties) {
        if (properties == null) {
            return null;
        }

        String nt = properties.getProperty(PROPERTY_NEGOTIATION_TYPE);
        if (null == nt) {
            nt = SSL_NEGOTIATION;
            logger.trace(
                format("Endpoint %s specific Negotiation type not found use global value: %s ", url, SSL_NEGOTIATION));
        }

        if (!"TLS".equals(nt) && !"plainText".equals(nt)) {
            throw new RuntimeException(
                format("Endpoint %s property of negotiationType has to be either TLS or plainText. value: '%s'",
                    url, nt
                ));
        }
        return nt;
    }

    private static String readSslProviderProperty(String url, Properties properties) {
        if (properties == null) {
            return null;
        }

        String sslp = properties.getProperty(PROPERTY_SSL_PROVIDER);

        if (null == sslp) {
            sslp = SSL_PROVIDER;
            logger.trace(format("Endpoint %s specific SSL provider not found use global value: %s ",
                url, SSL_PROVIDER
            ));
        }
        if (!"openSSL".equals(sslp) && !"JDK".equals(sslp)) {
            throw new RuntimeException(
                format("Endpoint %s property of sslProvider has to be either openSSL or JDK. value: '%s'",
                    url, sslp
                ));
        }
        return sslp;
    }

    private static void validatePropertyExclusivity(Properties properties, String propertyKey1, String propertyKey2) {
        if (properties.containsKey(propertyKey1) && properties.containsKey(propertyKey2)) {
            throw new RuntimeException(
                format("Properties \"%s\" and \"%s\" cannot both be set", propertyKey1, propertyKey2)
            );
        }
    }

    private static class GrpcsContext {

        private final String cn;
        private final byte[] pemBytes;

        private GrpcsContext(
            String cn, byte[] pemBytes) {
            this.cn = cn;
            this.pemBytes = pemBytes;
        }

        public Optional<String> getCn() {
            return Optional.ofNullable(cn);
        }

        public Optional<byte[]> getPemBytes() {
            return Optional.ofNullable(pemBytes);
        }
    }

    private static Optional<byte[]> getPEMFile(String url, Properties properties) {
        byte[] pemBytes;
        try (ByteArrayOutputStream bis = new ByteArrayOutputStream(64000)) {
            @SuppressWarnings("UseOfPropertiesAsHashtable") byte[] pb = (byte[]) properties.get(PROPERTY_PEM_BYTES);
            if (null != pb) {
                bis.write(pb);
            }
            if (properties.containsKey(PROPERTY_PEM_FILE)) {

                String pemFile = properties.getProperty(PROPERTY_PEM_FILE);

                String[] pems = PEMFILE_SPLIT_PATTERN.split(pemFile);

                for (String pem : pems) {
                    if (null != pem && !pem.isEmpty()) {
                        try {
                            bis.write(Files.readAllBytes(Paths.get(pem)));
                        } catch (IOException e) {
                            throw new RuntimeException(format(
                                "Failed to read certificate file %s",
                                new File(pem).getAbsolutePath()
                            ), e);
                        }
                    }
                }

            }
            pemBytes = bis.toByteArray();
            logger.trace(format("Endpoint %s pemBytes: %s", url, Hex.encodeHexString(pemBytes)));

            if (pemBytes.length == 0) {
                return Optional.empty();
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to read CA certificates file %s", e);
        }
        return Optional.of(pemBytes);
    }

    SslContextBuilder getSslContextBuilder(
        X509Certificate[] clientCert, PrivateKey clientKey, SslProvider sslprovider) {
        SslContextBuilder clientContextBuilder = GrpcSslContexts.configure(SslContextBuilder.forClient(), sslprovider);
        if (clientKey != null && clientCert != null) {
            clientContextBuilder = clientContextBuilder.keyManager(clientKey, clientCert);
        } else {
            logger.debug(format("Endpoint %s with no ssl context", url));
        }
        return clientContextBuilder;
    }

    byte[] getClientTLSCertificateDigest() {
        //The digest must be SHA256 over the DER encoded certificate. The PEM has the exact DER sequence in hex encoding around the begin and end markers

        if (tlsClientCertificatePEMBytes != null && clientTLSCertificateDigest == null) {

            String pemCert = new String(tlsClientCertificatePEMBytes, UTF_8);
            byte[] derBytes = Base64.getDecoder().decode(
                WHITESPACE_PATTERN.matcher(CERT_BODY_PATTERN.matcher(pemCert).replaceAll("")).replaceAll("").trim()
            );

            Digest digest = new SHA256Digest();
            clientTLSCertificateDigest = new byte[digest.getDigestSize()];
            digest.update(derBytes, 0, derBytes.length);
            digest.doFinal(clientTLSCertificateDigest, 0);
        }

        return clientTLSCertificateDigest;
    }

    private static final Pattern METHOD_PATTERN = Pattern.compile("grpc\\.NettyChannelBuilderOption\\.([^.]*)$");
    private static final Map<Class<?>, Class<?>> WRAPPERS_TO_PRIM = new Builder<Class<?>, Class<?>>()
                                                                        .put(Boolean.class, boolean.class)
                                                                        .put(Byte.class, byte.class)
                                                                        .put(Character.class, char.class)
                                                                        .put(Double.class, double.class)
                                                                        .put(Float.class, float.class)
                                                                        .put(Integer.class, int.class)
                                                                        .put(Long.class, long.class)
                                                                        .put(Short.class, short.class)
                                                                        .put(Void.class, void.class).build();

    private void addNettyBuilderProps(NettyChannelBuilder channelBuilder, Properties props)
        throws InvocationTargetException, IllegalAccessException, NoSuchMethodException {

        if (props == null) {
            return;
        }

        for (Entry<?, ?> es : props.entrySet()) {
            Object methodprop = es.getKey();
            if (methodprop == null) {
                continue;
            }
            String methodprops = String.valueOf(methodprop);

            Matcher match = METHOD_PATTERN.matcher(methodprops);

            String methodName = null;

            if (match.matches() && match.groupCount() == 1) {
                methodName = match.group(1).trim();

            }
            if (null == methodName || "forAddress".equals(methodName) || "build".equals(methodName)) {
                continue;
            }

            Object parmsArrayO = es.getValue();
            Object[] parmsArray =
                !(parmsArrayO instanceof Object[]) ? new Object[]{parmsArrayO} : (Object[]) parmsArrayO;

            Class<?>[] classParms = new Class<?>[parmsArray.length];
            for (int i = 0; i < parmsArray.length; i++) {
                Object oparm = parmsArray[i];

                if (null == oparm) {
                    classParms[i] = Object.class;
                    continue;
                }

                Class<?> unwrapped = WRAPPERS_TO_PRIM.get(oparm.getClass());
                if (null != unwrapped) {
                    classParms[i] = unwrapped;
                } else {
                    Class<?> clz = oparm.getClass();

                    Class<?> ecz = clz.getEnclosingClass();
                    if (null != ecz && ecz.isEnum()) {
                        clz = ecz;
                    }

                    classParms[i] = clz;
                }
            }

            Utils.invokeMethod(channelBuilder, methodName, classParms, parmsArray);

            if (logger.isTraceEnabled()) {
                logger.trace(format("Endpoint with url: %s set managed channel builder method %s (%s) ", url,
                    methodName, Arrays.toString(parmsArray)
                ));
            }
        }
    }

    private Pair<PrivateKey, X509Certificate[]> readClientTLSProps(String url, Properties properties) {
        if (properties == null) {
            return Pair.create(null, null);
        }

        // check for mutual TLS - both clientKey and clientCert must be present
        validatePropertyExclusivity(properties, CLIENT_KEY_FILE, CLIENT_KEY_BYTES);
        validatePropertyExclusivity(properties, CLIENT_CERT_FILE, CLIENT_CERT_BYTES);

        byte[] ckb;
        byte[] ccb;
        if (properties.containsKey(CLIENT_KEY_FILE) || properties.containsKey(CLIENT_CERT_FILE)) {
            String propertyClientKeyFile = properties.getProperty(CLIENT_KEY_FILE);
            String propertyClientCertFile = properties.getProperty(CLIENT_CERT_FILE);

            if (propertyClientKeyFile == null || propertyClientCertFile == null) {
                throw new RuntimeException(format(
                    "Properties \"%s\" and \"%s\" must both be set or both be null",
                    CLIENT_KEY_FILE, CLIENT_CERT_FILE
                ));
            }

            try {
                logger.trace(format("Endpoint %s reading clientKeyFile: %s", url,
                    new File(propertyClientKeyFile).getAbsolutePath()
                ));
                ckb = Files.readAllBytes(Paths.get(propertyClientKeyFile));
                logger.trace(format("Endpoint %s reading clientCertFile: %s", url,
                    new File(propertyClientCertFile).getAbsolutePath()
                ));
                ccb = Files.readAllBytes(Paths.get(propertyClientCertFile));
            } catch (IOException e) {
                throw new RuntimeException("Failed to parse TLS client key and/or cert", e);
            }
        } else if (properties.containsKey(CLIENT_KEY_BYTES) || properties.containsKey(CLIENT_CERT_BYTES)) {
            //noinspection UseOfPropertiesAsHashtable
            ckb = (byte[]) properties.get(CLIENT_KEY_BYTES);
            //noinspection UseOfPropertiesAsHashtable
            ccb = (byte[]) properties.get(CLIENT_CERT_BYTES);

            if (ckb == null || ccb == null) {
                throw new RuntimeException(format(
                    "Properties \"%s\" and \"%s\" must both be set or both be null",
                    CLIENT_KEY_BYTES, CLIENT_CERT_BYTES
                ));
            }
        } else {
            return Pair.create(null, null);
        }

        return parsePrivateKey(url, ckb, ccb);
    }

    private Pair<PrivateKey, X509Certificate[]> parsePrivateKey(String url, byte[] ckb, byte[] ccb) {
        String what = "private key";
        byte[] whatBytes = new byte[0];
        try {

            CryptoPrimitives cp;
            try {
                cp = new CryptoPrimitives();
            } catch (ClassNotFoundException | IllegalAccessException | InstantiationException e) {
                throw new RuntimeException(e);
            }

            logger.trace("client TLS private key bytes size:" + ckb.length);
            whatBytes = ckb;
            logger.trace("client TLS key bytes:" + Hex.encodeHexString(ckb));
            PrivateKey clientKey = cp.bytesToPrivateKey(ckb);
            logger.trace("converted TLS key.");
            what = "certificate";
            whatBytes = ccb;
            logger.trace("client TLS certificate bytes:" + Hex.encodeHexString(ccb));
            X509Certificate[] clientCert = {(X509Certificate) cp.bytesToCertificate(ccb)};
            logger.trace("converted client TLS certificate.");
            tlsClientCertificatePEMBytes = ccb; // Save this away it's the exact pem we used.

            return new Pair<>(clientKey, clientCert);
        } catch (CryptoException e) {
            logger.error(format("Failed endpoint %s to parse %s TLS client %s", url, what, new String(
                whatBytes,
                UTF_8
            )));
            throw new RuntimeException(format("Failed endpoint %s to parse TLS client %s", url, what), e);
        }
    }

    ManagedChannelBuilder<?> getChannelBuilder() {
        return channelBuilder;
    }

    String getHost() {
        return addr;
    }

    int getPort() {
        return port;
    }

    static Endpoint createEndpoint(String url, Properties properties) {

        return new Endpoint(url, properties);

    }

}
