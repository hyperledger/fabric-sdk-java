/*
 *
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

package org.hyperledger.fabric.sdk.testutils;

import java.io.ByteArrayInputStream;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.security.PrivateKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.zip.GZIPInputStream;

import com.google.protobuf.ByteString;
import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;
import org.hyperledger.fabric.protos.msp.Identities;
import org.hyperledger.fabric.sdk.Channel;
import org.hyperledger.fabric.sdk.Enrollment;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.Orderer;
import org.hyperledger.fabric.sdk.Peer;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.hyperledger.fabric.sdk.identity.SigningIdentity;
import org.hyperledger.fabric.sdk.identity.X509Enrollment;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.junit.Assert;

import static java.lang.String.format;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

//import org.hyperledger.fabric.sdk.MockUser;
//import org.hyperledger.fabric.sdk.ClientTest.MockEnrollment;

public class TestUtils {

    private TestUtils() {
    }

    /**
     * Sets the value of a field on an object
     *
     * @param o         The object that contains the field
     * @param fieldName The name of the field
     * @param value     The new value
     * @return The previous value of the field
     */
    public static Object setField(Object o, String fieldName, Object value) {
        Object oldVal = null;
        try {
            final Field field = getFieldInt(o.getClass(), fieldName);
            field.setAccessible(true);
            oldVal = field.get(o);
            field.set(o, value);
        } catch (Exception e) {
            throw new RuntimeException("Cannot get value of field " + fieldName, e);
        }
        return oldVal;
    }

    /**
     * Invokes method on object.
     * Used to access private methods.
     *
     * @param o          The object that contains the field
     * @param methodName The name of the field
     * @param args       The arguments.
     * @return Result of method.
     */
    public static Object invokeMethod(Object o, String methodName, Object... args) throws Throwable {

        Method[] methods = o.getClass().getDeclaredMethods();
        List<Method> reduce = new ArrayList<>(Arrays.asList(methods));
        for (Iterator<Method> i = reduce.iterator(); i.hasNext();
        ) {
            Method m = i.next();
            if (!methodName.equals(m.getName())) {
                i.remove();
                continue;
            }
            Class<?>[] parameterTypes = m.getParameterTypes();
            if (parameterTypes.length != args.length) {
                i.remove();
                continue;
            }
        }
        if (reduce.isEmpty()) {
            throw new RuntimeException(String.format("TEST ISSUE Could not find method %s on %s with %d arguments.",
                    methodName, o.getClass().getName(), args.length));
        }
        if (reduce.size() > 1) {
            throw new RuntimeException(String.format("TEST ISSUE Could not find unique method %s on %s. Found with %d matches.",
                    methodName, o.getClass().getName(), reduce.size()));
        }

        Method method = reduce.iterator().next();
        method.setAccessible(true);
        try {
            return method.invoke(o, args);
        } catch (IllegalAccessException e) {
            throw e;
        } catch (InvocationTargetException e) {
            throw e.getTargetException();
        }

    }

    /**
     * Gets the value of a field on an object
     *
     * @param o         The object that contains the field
     * @param fieldName The name of the field
     * @return The value of the field
     */
    public static Object getField(Object o, String fieldName) {

        try {
            final Field field = getFieldInt(o.getClass(), fieldName);

            return field.get(o);
        } catch (Exception e) {
            throw new RuntimeException("Cannot get value of field " + fieldName, e);
        }
    }

    private static Field getFieldInt(Class o, String name) throws NoSuchFieldException {
        Field ret;
        try {
            ret = o.getDeclaredField(name);
        } catch (NoSuchFieldException e) {

            Class superclass = o.getSuperclass();
            if (null != superclass) {
                ret = getFieldInt(superclass, name);

            } else {
                throw e;
            }

        }
        ret.setAccessible(true);
        return ret;
    }

    /**
     * Reset config.
     */
    public static void resetConfig() {

        try {
            final Field field = Config.class.getDeclaredField("config");
            field.setAccessible(true);
            field.set(Config.class, null);
            Config.getConfig();
        } catch (Exception e) {
            throw new RuntimeException("Cannot reset config", e);
        }

    }

    /**
     * Sets a Config property value
     * <p>
     * The Config instance is initialized once on startup which means that
     * its properties don't change throughout its lifetime.
     * This method allows a Config property to be changed temporarily for testing purposes
     *
     * @param key   The key of the property (eg Config.LOGGERLEVEL)
     * @param value The new value
     * @return The previous value
     */
    public static String setConfigProperty(String key, String value) throws Exception {

        String oldVal = null;

        try {
            Config config = Config.getConfig();

            final Field sdkPropertiesInstance = config.getClass().getDeclaredField("sdkProperties");
            sdkPropertiesInstance.setAccessible(true);

            final Properties sdkProperties = (Properties) sdkPropertiesInstance.get(config);
            oldVal = sdkProperties.getProperty(key);
            sdkProperties.put(key, value);

        } catch (Exception e) {
            throw new RuntimeException("Failed to set Config property " + key, e);
        }

        return oldVal;
    }

    public static MockUser getMockUser(String name, String mspId) {
        return new MockUser(name, mspId);
    }

    public static Enrollment getMockEnrollment(String cert) {
        return new X509Enrollment(new MockPrivateKey(), cert);
    }

    public static MockSigningIdentity getMockSigningIdentity(String cert, String mspId, Enrollment enrollment) {
        return new MockSigningIdentity(cert, mspId, enrollment);
    }

    public static Enrollment getMockEnrollment(PrivateKey key, String cert) {
        return new X509Enrollment(key, cert);
    }

    public static ArrayList tarBytesToEntryArrayList(byte[] bytes) throws Exception {

        ArrayList<String> ret = new ArrayList<>();

        TarArchiveInputStream tarArchiveInputStream = new TarArchiveInputStream(new GZIPInputStream(new ByteArrayInputStream(bytes)));

        for (TarArchiveEntry ta = tarArchiveInputStream.getNextTarEntry(); null != ta; ta = tarArchiveInputStream.getNextTarEntry()) {

            Assert.assertTrue(format("Tar entry %s is not a file.", ta.getName()), ta.isFile()); //we only expect files.
            ret.add(ta.getName());

        }

        return ret;

    }

    public static void assertArrayListEquals(String failmsg, ArrayList expect, ArrayList actual) {
        ArrayList expectSort = new ArrayList(expect);
        Collections.sort(expectSort);
        ArrayList actualSort = new ArrayList(actual);
        Collections.sort(actualSort);
        Assert.assertArrayEquals(failmsg, expectSort.toArray(), actualSort.toArray());
    }

    public static Matcher<String> matchesRegex(final String regex) {
        return new TypeSafeMatcher<String>() {
            @Override
            public void describeTo(Description description) {

            }

            @Override
            protected boolean matchesSafely(final String item) {
                return item.matches(regex);
            }
        };
    }

    /**
     * Just for testing remove all peers and orderers and add them back.
     *
     * @param client
     * @param channel
     */
    public static void testRemovingAddingPeersOrderers(HFClient client, Channel channel) {
        Map<Peer, Channel.PeerOptions> perm = new HashMap<>();

        assertTrue(channel.isInitialized());
        assertFalse(channel.isShutdown());

        try {
            Thread.sleep(1500); // time needed let channel get config block
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }

        channel.getPeers().forEach(peer -> {
            try {
                perm.put(peer, channel.getPeersOptions(peer));
                channel.removePeer(peer);
            } catch (InvalidArgumentException e) {
                throw new RuntimeException(e);
            }
        });

        perm.forEach((peer, value) -> {
            try {

                Peer newPeer = client.newPeer(peer.getName(), peer.getUrl(), peer.getProperties());
                channel.addPeer(newPeer, value);

            } catch (InvalidArgumentException e) {
                throw new RuntimeException(e);
            }
        });

        List<Orderer> removedOrders = new ArrayList<>();

        for (Orderer orderer : channel.getOrderers()) {
            try {
                channel.removeOrderer(orderer);
                removedOrders.add(orderer);
            } catch (InvalidArgumentException e) {
                throw new RuntimeException(e);
            }

        }
        removedOrders.forEach(orderer -> {
            try {
                Orderer newOrderer = client.newOrderer(orderer.getName(), orderer.getUrl(), orderer.getProperties());
                channel.addOrderer(newOrderer);
            } catch (InvalidArgumentException e) {
                throw new RuntimeException(e);
            }

        });
    }

    private static class MockPrivateKey implements PrivateKey {
        private static final long serialVersionUID = 1L;

        private MockPrivateKey() {
        }

        @Override
        public String getAlgorithm() {
            return null;
        }

        @Override
        public String getFormat() {
            return null;
        }

        @Override
        public byte[] getEncoded() {
            return new byte[0];
        }
    }

    private static final String MOCK_CERT = "-----BEGIN CERTIFICATE-----" +
            "MIICGjCCAcCgAwIBAgIRAPDmqtljAyXFJ06ZnQjXqbMwCgYIKoZIzj0EAwIwczEL" +
            "MAkGA1UEBhMCVVMxEzARBgNVBAgTCkNhbGlmb3JuaWExFjAUBgNVBAcTDVNhbiBG" +
            "cmFuY2lzY28xGTAXBgNVBAoTEG9yZzEuZXhhbXBsZS5jb20xHDAaBgNVBAMTE2Nh" +
            "Lm9yZzEuZXhhbXBsZS5jb20wHhcNMTcwNjIyMTIwODQyWhcNMjcwNjIwMTIwODQy" +
            "WjBbMQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQGA1UEBxMN" +
            "U2FuIEZyYW5jaXNjbzEfMB0GA1UEAwwWQWRtaW5Ab3JnMS5leGFtcGxlLmNvbTBZ" +
            "MBMGByqGSM49AgEGCCqGSM49AwEHA0IABJve76Fj5T8Vm+FgM3p3TwcnW/npQlTL" +
            "P+fY0fImBODqQLTkBokx4YiKcQXQl4m1EM1VAbOhAlBiOfNRNL0W8aGjTTBLMA4G" +
            "A1UdDwEB/wQEAwIHgDAMBgNVHRMBAf8EAjAAMCsGA1UdIwQkMCKAIPz3drAqBWAE" +
            "CNC+nZdSr8WfZJULchyss2O1uVoP6mIWMAoGCCqGSM49BAMCA0gAMEUCIQDatF1P" +
            "L7SavLsmjbFxdeVvLnDPJuCFaAdr88oE2YuAvwIgDM4qXAcDw/AhyQblWR4F4kkU" +
            "NHvr441QC85U+V4UQWY=" +
            "-----END CERTIFICATE-----";

    //  This is the private key for the above cert. Right now we don't need this and there's some class loader issues doing this here.

//    private static final String MOCK_NOT_SO_PRIVATE_KEY = "-----BEGIN PRIVATE KEY-----\n" +
//            "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQghnA7rdgbZi/wndus\n" +
//            "iXjyf0KgE6OKZjQ+5INjwelRAC6hRANCAASb3u+hY+U/FZvhYDN6d08HJ1v56UJU\n" +
//            "yz/n2NHyJgTg6kC05AaJMeGIinEF0JeJtRDNVQGzoQJQYjnzUTS9FvGh\n" +
//            "-----END PRIVATE KEY-----";

    //    private static final  PrivateKey mockNotSoPrivateKey = getPrivateKeyFromBytes(MOCK_NOT_SO_PRIVATE_KEY.getBytes(StandardCharsets.UTF_8));
//
//    static PrivateKey getPrivateKeyFromBytes(byte[] data) {
//        try {
//            final Reader pemReader = new StringReader(new String(data));
//
//            final PrivateKeyInfo pemPair;
//            try (PEMParser pemParser = new PEMParser(pemReader)) {
//                pemPair = (PrivateKeyInfo) pemParser.readObject();
//            }
//
//            return new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).getPrivateKey(pemPair);
//        } catch (IOException e) {
//            throw new RuntimeException(e);
//        }
//    }
    public static class MockUser implements User {
        private String name;
        private String mspId;
        private Enrollment enrollment;

        public String getEnrollmentSecret() {
            return enrollmentSecret;
        }

        private String enrollmentSecret;

        private MockUser(String name, String mspId) {
            this.name = name;
            this.mspId = mspId;
            setEnrollment(getMockEnrollment(MOCK_CERT));
        }

        public void setEnrollment(Enrollment e) {
            this.enrollment = e;
        }

        @Override
        public String getName() {
            return name;
        }

        @Override
        public Set<String> getRoles() {
            return null;
        }

        @Override
        public String getAccount() {
            return null;
        }

        @Override
        public String getAffiliation() {
            return null;
        }

        @Override
        public Enrollment getEnrollment() {
            return enrollment;
        }

        @Override
        public String getMspId() {
            return mspId;
        }

        public void setEnrollmentSecret(String enrollmentSecret) {
            this.enrollmentSecret = enrollmentSecret;
        }

    }

    public static class MockSigningIdentity implements SigningIdentity {
        private String cert;
        private String mspId;
        private Enrollment enrollment;

        public MockSigningIdentity(String cert, String mspId, Enrollment enrollment) {
            this.cert = cert;
            this.mspId = mspId;
            this.enrollment = enrollment;
        }

        @Override
        public byte[] sign(byte[] msg) throws CryptoException {
            try {
                return CryptoSuite.Factory.getCryptoSuite().sign(this.enrollment.getKey(), msg);
            } catch (Exception e) {
                throw new CryptoException(e.getMessage(), e);
            }
        }

        @Override
        public boolean verifySignature(byte[] msg, byte[] sig) throws CryptoException {
            return false;
        }

        @Override
        public Identities.SerializedIdentity createSerializedIdentity() {
            return Identities.SerializedIdentity.newBuilder()
                    .setIdBytes(ByteString.copyFromUtf8(cert))
                    .setMspid(mspId).build();
        }
    }

}

