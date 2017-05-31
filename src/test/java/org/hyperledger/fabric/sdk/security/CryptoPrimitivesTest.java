/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

package org.hyperledger.fabric.sdk.security;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Properties;

import javax.xml.bind.DatatypeConverter;

import org.apache.commons.compress.utils.IOUtils;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.helper.Config;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

public class CryptoPrimitivesTest {

    // run End2EndIT test and copy from first peer ProposalResponse ( fabric at
    // commit level 230f3cc )
    public static final String plainTextHex = "0A205E87B04D3B137E4F2BD2B7E435C96D86E62F3DA5147863A2051F39803AB519BD12E60F0AE30F02046C636363010D6578616D706C655F63632E676F00010D6578616D706C655F63632E676F009D0F0A0D6578616D706C655F63632E676F1201301A880F0A2B0801120F120D6578616D706C655F63632E676F1A160A04696E69740A01610A033130300A01620A03323030120708B2B4FFAF9D2B1ACF0E1F8B08000000000000FFED586D73DA4610CE57F42BB69A26869420C0A49E71EB0F603B2D93165C709A64624FE610075C2D24727702D34EFE7B77EF2410183B4E4CD2990E3B9380B8BBBD67DF9E5DF924F2AFB81C88803FFA6A52AE94CB3FD66A50B6B2FE59AE1E54A0B25FAE552BFBD5F2F30328572ACF0F6A8FA0FCF5202D25569AC947E507DFB56EDC16A07D0B79D169FF0EA3F984CB80F7875C7A03D693C27FE6FB3C9C3A8072DC3E7B0B25F8FE97F659FDFC574F49DFEBC522E83FF3474C847ED4E79ED9F7BADD7979D2ECA41BCD6F9D572D18462042747210C0DA3980274F603C5DA8EE89705DF5CA1ABF66E349C0DFFB7E6918FDD78EFB9FC8B7F0E9DDF55FA9D69E574DFD570EF66BCF0FF6B1FEABD5DAC1AEFEBF85784F9DE36832976238D2D06CFC0EC7919C94A05AAEFC08752CD90E2D28E870C5E594F74B8EF39B406A50BC0F71D8E712F488437DC27CFC48568AF027974A4421544B65C8D3063759720B3F39F32886319B4318698815470542013520E0D73E9F68640BF0234C4AC1429FC34CE891B924515172DE260AA29E46960086BB27F834C8EE02A61D27978391D69343CF9BCD66256640962239F402BB4979BF358F4F5BDDD36708D4715E8501570A24FF100B89F6F5E6C02608C3673D0417B0194412D850725CD3446A3093428B705804150DF48C49EEF485D252F462BDE29F14141A9ADD801E6221B8F52E34BB2E34EADD66B7E8BC6E9EFFDA7E750EAFEB9D4EBD75DE3CED42BB8324DC3A699E37DB2D7C7A01F5D65B78D96C9D1481A377F0127E3D91841D010AF21C05AACBF9CAE583C8825113EE8B81F0D1A27018B32147869E7219A221806D602C14C54E21B4BE1388B1D04C9BE71BE6949CA79EE3A057AF48C91863E1380E5E1F490D7927E7722923A95CFC36186BFA40CBFD289CBA18197788C0E35E0903EDDDEC3E9E1F49EE2DFB8B1A89B1EB141CC7F3A04B06F2E3458348080C94F91D960BE679CC438BDFD178CB8DC38828F635FCE37C749C411CFA98ADF0746D53019AA1D079A5E31E1090D262A58B3F35438DE313F3715BFEDD656FAE31FD8DE105D49A7B5F0426870A0E8F80CE977EE1FA055E4380EA61FF8C4936E6785EE50B4E6ECA24D48BD02050140B1434F734D498635C25EB5316E016FC1FD34FD37A5D29AE6114057D3C93ECC2FB2D0674B41840C0C33CA128C0774750235839C9752C43084590A055A5169FE5DD26DA2525479784F1B887E1C6AAC2A331B95195E0F41A7387321E6A2E2246A7E51002B947B040FC6DF36D11362757872363FFBBF2253E18EC848D9C6132A154D79130D8DE552E0B062CAD234C447627D02512F403C7CC01D41EDB24675997589CB9468AA48A481A7722D9FFBA48B0164A6718603DC8BBE412C4F0B89FC494BE5E846E3113E782F5F16B641AEB5E6C57F42D320FB66A9C5C6A0BA6D859ACBBB4258FB96413329FDAD8D411CB93EA42E13E26DA006F52DDD8ACBAF199AAB33FE27F7717E11F3197F32FABC25B63F72ABC0AA359082A9E106B2125FB38A662A03E1AAA39972C54CC542BD2DB15573061732A052A8B374888023BE3404663A853401A7752C834BAE25F067F9030C667708909417A8EE2E00A03C0BD973B1607136F9860AD10C9CF50DD0E8F308D5A99D250CDDC9350061C21EE3E0FD02A8B1B4372621EA9390127669C5BFF53204C612C31E9923D6A7C6E5DB7F9860F94588B0BE849AC5C7043EF87452666D4AE6B1D634FFD22D474F086F24F458C250982038E7F65986120247A35F57911C638E7428FE3CCC129187BD6397B45D833E6E017E4AB3DBA7CCFE6FFEDB9BC4078572627C9FAEED276B38D898D9E4961A1676C866EB30FBE318B0B59AB6843D3DFAE61169765358882209AD909B30A21D6AD99B6A06231A595B0E89E95CBD506663C87E59FE907269FB21D818C6D9FB40F717EA6176F8ED07DD336466C8AEEA6E338DE1B3A37654E4BE959F22EC54AD92699219CA4B37C56837CC170B63713F310211BB8EEA264165751D17CB2D5DADAA117874184E368A2C626C3FBF5666ED327BFB8A140ADB4F109D31ADB33ADB105D31A779AD658310D237E86B517499B08FC9AFBB1997C736FB636EC601BC3410F2DCED4111B23606418BE24F5D551281326C4603E9EC11B6B1CFE603E7EA01FB6331AF51851E0FF613EF2BCF50929DD976827877527198F1DA5FE2277AD3AABB098B16E6F48B619DDCEFC998EFA50EE5FA7D9CA7668B6B224CFC3257B3ACB266CD2E28ACF978C69B306DFE6B3C99212031E7A18E7599765B961E3DC8BF8CC806BB8D864B0E4F44A4FD141B308A7E9D3C6F0CC2BD6EDB1FA70AF79F91EA14A3A6EDA8E6FF4E2BB9AE796A6446A91E91F782638E222EBA06BEDE0B6A159DEA73F7E598FFB0BAFEE7035A1FDEE3F17EE295973E11E5E6C6A05E615D0456AABE33FF7C2FDE8DEEE8B54F17244DDD8196FBFBF853B2C133FE0DA75F52DF4BBD19E5157BC70EBE69EC5C28D46BBBC37CBE836BF497D142A7EF858193ACF2048306622937D29A4BF2FE50D75A4F1A2ACC660499D0FD194F502D818BF2C1EE33B8A94343966CF2F4BEB101E2BD738CB38E7A3F35FFFA576273BD9C94E76B2939DEC64273BD9C94E1E26FF02F35EC2D1002800000D6578616D706C655F63632E676F000201610003313030016200033230300A0744454641554C54129A072D2D2D2D2D424547494E202D2D2D2D2D0A4D4949436A444343416A4B6741774942416749554245567773537830546D7164627A4E776C654E42427A6F4954307777436759494B6F5A497A6A3045417749770A667A454C4D416B474131554542684D4356564D78457A415242674E5642416754436B4E6862476C6D62334A7561574578466A415542674E564241635444564E680A62694247636D467559326C7A59323878487A416442674E5642416F54466B6C7564475679626D5630494664705A47646C64484D7349456C75597934784444414B0A42674E564241735441316458567A45554D4249474131554541784D4C5A586868625842735A53356A623230774868634E4D5459784D5445784D5463774E7A41770A5768634E4D5463784D5445784D5463774E7A4177576A426A4D517377435159445651514745774A56557A45584D4255474131554543424D4F546D3979644767670A5132467962327870626D45784544414F42674E564241635442314A68624756705A326778477A415A42674E5642416F54456B6835634756796247566B5A3256790A49455A68596E4A70597A454D4D416F474131554543784D44513039514D466B77457759484B6F5A497A6A3043415159494B6F5A497A6A304441516344516741450A4842754B73414F34336873344A4770466669474D6B422F7873494C54734F766D4E32576D77707350485A4E4C36773848576533784350517464472F584A4A765A0A2B433735364B457355424D337977355054666B7538714F42707A43427044414F42674E56485138424166384542414D4342614177485159445652306C424259770A464159494B7759424251554841774547434373474151554642774D434D41774741315564457745422F7751434D414177485159445652304F42425945464F46430A6463555A346573336C746943674156446F794C66567050494D42384741315564497751594D4261414642646E516A32716E6F492F784D55646E3176446D6447310A6E4567514D43554741315564455151654D427943436D31356147397A6443356A62323243446E6433647935746557687663335175593239744D416F47434371470A534D343942414D43413067414D4555434944663948626C34786E337A3445774E4B6D696C4D396C58324671346A5770416152564239374F6D56456579416945410A32356144505148474771324176684B54307776743038635831475447434962666D754C704D774B516A33383D0A2D2D2D2D2D454E44202D2D2D2D2D0A";
    public static final String sigHex = "3045022100880FFD28A54ACDCBDC8C54EC7927143A734199EF6BC659FBE5312C736F40769E02202A4EA0F2060AEE5E59D9440F31748E1BD01DB32031DBD7A12791B16A8E3E4D3D";
    public static final String pemCertHex = "2D2D2D2D2D424547494E202D2D2D2D2D0A4D4949436A444343416A4B6741774942416749554245567773537830546D7164627A4E776C654E42427A6F4954307777436759494B6F5A497A6A3045417749770A667A454C4D416B474131554542684D4356564D78457A415242674E5642416754436B4E6862476C6D62334A7561574578466A415542674E564241635444564E680A62694247636D467559326C7A59323878487A416442674E5642416F54466B6C7564475679626D5630494664705A47646C64484D7349456C75597934784444414B0A42674E564241735441316458567A45554D4249474131554541784D4C5A586868625842735A53356A623230774868634E4D5459784D5445784D5463774E7A41770A5768634E4D5463784D5445784D5463774E7A4177576A426A4D517377435159445651514745774A56557A45584D4255474131554543424D4F546D3979644767670A5132467962327870626D45784544414F42674E564241635442314A68624756705A326778477A415A42674E5642416F54456B6835634756796247566B5A3256790A49455A68596E4A70597A454D4D416F474131554543784D44513039514D466B77457759484B6F5A497A6A3043415159494B6F5A497A6A304441516344516741450A4842754B73414F34336873344A4770466669474D6B422F7873494C54734F766D4E32576D77707350485A4E4C36773848576533784350517464472F584A4A765A0A2B433735364B457355424D337977355054666B7538714F42707A43427044414F42674E56485138424166384542414D4342614177485159445652306C424259770A464159494B7759424251554841774547434373474151554642774D434D41774741315564457745422F7751434D414177485159445652304F42425945464F46430A6463555A346573336C746943674156446F794C66567050494D42384741315564497751594D4261414642646E516A32716E6F492F784D55646E3176446D6447310A6E4567514D43554741315564455151654D427943436D31356147397A6443356A62323243446E6433647935746557687663335175593239744D416F47434371470A534D343942414D43413067414D4555434944663948626C34786E337A3445774E4B6D696C4D396C58324671346A5770416152564239374F6D56456579416945410A32356144505148474771324176684B54307776743038635831475447434962666D754C704D774B516A33383D0A2D2D2D2D2D454E44202D2D2D2D2D0A";

    // File create_key_cert_for_testing.md has info on the other keys and
    // certificates used in this test suite

    private static byte[] plainText, sig, pemCert;

    private static KeyStore trustStore;

    private static KeyFactory kf;

    private static CertificateFactory cf;

    private static CryptoPrimitives crypto;

    private static Certificate testCACert;

    private static Config config ;

    @BeforeClass
    public static void setUpBeforeClass() throws Exception {
        config = Config.getConfig();

        plainText = DatatypeConverter.parseHexBinary(plainTextHex);
        sig = DatatypeConverter.parseHexBinary(sigHex);
        pemCert = DatatypeConverter.parseHexBinary(pemCertHex);

        kf = KeyFactory.getInstance("EC");

        cf = CertificateFactory.getInstance("X.509");

        crypto = new CryptoPrimitives();
        crypto.init();

    }

    @Before
    public void setUp() throws Exception {
        // TODO should do this in @BeforeClass. Need to find out how to get to
        // files from static junit method
        BufferedInputStream bis = new BufferedInputStream(this.getClass().getResourceAsStream("/ca.crt"));
        testCACert = cf.generateCertificate(bis);
        bis.close();
        crypto.addCACertificateToTrustStore(testCACert, "ca");

        bis = new BufferedInputStream(this.getClass().getResourceAsStream("/keypair-signed.crt"));
        Certificate cert = cf.generateCertificate(bis);
        bis.close();

        // TODO: get PEM file without dropping down to BouncyCastle ?
        PEMParser pem = new PEMParser(new FileReader(this.getClass().getResource("/keypair-signed.key").getFile()));
        PEMKeyPair bcKeyPair = (PEMKeyPair) pem.readObject();
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(bcKeyPair.getPrivateKeyInfo().getEncoded());
        PrivateKey key = kf.generatePrivate(keySpec);

        Certificate[] certificates = new Certificate[] {cert, testCACert};
        crypto.getTrustStore().setKeyEntry("key", key, "123456".toCharArray(), certificates);
        pem.close();
    }

    @Test
    public void testGetSetProperties() {
        CryptoPrimitives testCrypto = new CryptoPrimitives() ;
        Properties cryptoProps = testCrypto.getProperties() ;
        String hashAlg = config.getHashAlgorithm();
        assertEquals(cryptoProps.getProperty(Config.HASH_ALGORITHM), hashAlg);
        Properties propsIn = new Properties();
        try {
            propsIn.setProperty(Config.SECURITY_LEVEL, "384");
            testCrypto.setProperties(propsIn);
            cryptoProps = testCrypto.getProperties();
            assertEquals(cryptoProps.getProperty(Config.SECURITY_LEVEL), "384");
            testCrypto.setProperties(null);
            cryptoProps = testCrypto.getProperties();
            assertEquals(cryptoProps.getProperty(Config.HASH_ALGORITHM), hashAlg);
            assertEquals(cryptoProps.getProperty(Config.SECURITY_LEVEL), "384");
        } catch (CryptoException | InvalidArgumentException e) {
            fail("testGetSetProperties should not throw exception. Error: " + e.getMessage());
        }
    }

    @Test(expected=InvalidArgumentException.class)
    public void testSecurityLevel() throws InvalidArgumentException {
        CryptoPrimitives testCrypto = new CryptoPrimitives() ;
        testCrypto.setSecurityLevel(2001);
    }

    @Test(expected=InvalidArgumentException.class)
    public void testSetHashAlgorithm() throws InvalidArgumentException {
        CryptoPrimitives testCrypto = new CryptoPrimitives() ;
        testCrypto.setHashAlgorithm(null);
    }

    @Test(expected=InvalidArgumentException.class)
    public void testSetHashAlgorithmBadArg() throws InvalidArgumentException {
        CryptoPrimitives testCrypto = new CryptoPrimitives() ;
        testCrypto.setHashAlgorithm("FAKE");
    }

    @Test
    public void testGetTrustStore() {
        // getTrustStore should have created a KeyStore if setTrustStore hasn't
        // been called
        try {
            CryptoPrimitives myCrypto = new CryptoPrimitives();
            assertNotNull(myCrypto.getTrustStore());
        } catch (CryptoException e) {
            fail("getTrustStore() fails with : "+ e.getMessage());
        }
    }

    @Test
    public void testGetTrustStoreEntries() {
        // trust store should contain the entries
        try {
            assertNotNull(crypto.getTrustStore().getCertificateAlias(testCACert));
            assertNull(crypto.getTrustStore().getCertificate("testtesttest"));
        } catch (KeyStoreException | CryptoException e) {
            fail("testGetTrustStoreEntries should not have thrown exception. Error: " + e.getMessage());
        }
    }

    @Test
    public void testSetTrustStoreNull() {
        try {
            CryptoPrimitives myCrypto = new CryptoPrimitives();
            myCrypto.setTrustStore(null);
            fail("setTrustStore(null) should have thrown exception");
        } catch (Exception e) {

        }
    }

    @Test
    public void testSetTrustStore() {

            try {
                CryptoPrimitives myCrypto = new CryptoPrimitives();
                KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(null, null);
                myCrypto.setTrustStore(keyStore);
                assertSame(keyStore, myCrypto.getTrustStore());
            } catch (CryptoException | KeyStoreException | NoSuchAlgorithmException | CertificateException | InvalidArgumentException | IOException e) {
                fail("testSetTrustStore() should not have thrown Exception. Error: " + e.getMessage());
            }
    }

    @Test
    public void testSetTrustStoreDuplicateCert() {
        try {
            crypto.addCACertificateToTrustStore(testCACert, "ca"); //KeyStore overrides existing cert if same alias
        } catch (Exception e) {
            fail("testSetTrustStoreDuplicateCert should not have thrown Exception. Error: " + e.getMessage());
        }
    }

    @Test(expected=InvalidArgumentException.class)
    public void testAddCACertificateToTrustStoreNoAlias() throws InvalidArgumentException {
        try {
            crypto.addCACertificateToTrustStore(new File("something"), null);
        } catch (CryptoException e) {
            fail("testAddCACertificateToTrustStoreNoAlias should not throw CryptoException. Error: " + e.getMessage());
        }
    }

    @Test(expected=CryptoException.class)
    public void testAddCACertificateToTrustStoreNoFile() throws CryptoException {
        try {
            crypto.addCACertificateToTrustStore(new File("does/not/exist"), "abc");
        } catch (InvalidArgumentException e) {
            fail("testAddCACertificateToTrustStoreNoFile should not throw InvalidArgumentException. Error: " + e.getMessage());
        }
    }

    @Test(expected=InvalidArgumentException.class)
    public void testAddCACertificateToTrustStoreNoCert() throws InvalidArgumentException {
                try {
                    crypto.addCACertificateToTrustStore((Certificate) null, "abc");
                } catch (CryptoException e) {
                    fail("testAddCACertificateToTrustStoreNoCert should not have thrown CryptoException. Error " + e.getMessage());
                }
    }

    @Test(expected=CryptoException.class)
    public void testLoadCACertsBadInput() throws CryptoException {
        crypto.loadCACertificates(null);
    }

    @Test(expected=CryptoException.class)
    public void testLoadCACertsBytesBadInput() throws CryptoException {
        crypto.loadCACertificatesAsBytes(null);
    }

    @Test
    public void testLoadCACerts() {
        try {
            File certsFolder = new File("cacerts").getAbsoluteFile();
            Collection<File> certFiles = FileUtils.listFiles(certsFolder, new String[]{"pem"}, false);
            int numFiles = certFiles.size();
            int numStore = crypto.getTrustStore().size();

            BufferedInputStream bis;
            ArrayList<byte[]> certBytesList = new ArrayList<>();
            ArrayList<String> certIDs = new ArrayList<>();
            byte[] certB;
            for (File certFile : certFiles) {
                certB = IOUtils.toByteArray(new FileInputStream(certFile));
                certBytesList.add(certB);
                bis = new BufferedInputStream(new ByteArrayInputStream(certB));
                certIDs.add(Integer.toString(cf.generateCertificate(bis).hashCode()));
            }
            crypto.loadCACertificatesAsBytes(certBytesList);
            assertEquals(crypto.getTrustStore().size(), numStore+numFiles);
            for (String cID : certIDs) {
                assertTrue(crypto.getTrustStore().containsAlias(cID));
            }
        } catch (KeyStoreException | CryptoException | IOException | CertificateException e) {
            fail("testLoadCACerts should not have thrown exception. Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
    @Test
    public void testValidateNullCertificateByteArray() {
        assertFalse(crypto.validateCertificate((byte[]) null));
    }

    @Test
    public void testValidateNullCertificate() {
        assertFalse(crypto.validateCertificate((Certificate) null));
    }

    @Test
    public void testValidateCertificateByteArray() {
        assertTrue(crypto.validateCertificate(pemCert));
    }

    // Note:
    // For the validateBADcertificate tests, we use the fact that the trustStore
    // contains the peer CA cert
    // the keypair-signed cert is signed by us so it will not validate.

    @Test
    public void testValidateBadCertificateByteArray() {
        try {
            BufferedInputStream bis = new BufferedInputStream(this.getClass().getResourceAsStream("/notsigned.crt"));
            byte[] certBytes = IOUtils.toByteArray(bis);

            assertFalse(crypto.validateCertificate(certBytes));
        } catch (IOException e) {
            Assert.fail("cannot read cert file");
        }
    }

    @Test
    public void testValidateBadCertificate() {
        try {
            BufferedInputStream bis = new BufferedInputStream(this.getClass().getResourceAsStream("/notsigned.crt"));
            Certificate cert = cf.generateCertificate(bis);

            assertFalse(crypto.validateCertificate(cert));
        } catch (CertificateException e) {
            Assert.fail("cannot read cert file");
        }
    }

    @Test
    public void testValidateCertificate() {
        try {
            BufferedInputStream pem = new BufferedInputStream(new ByteArrayInputStream(pemCert));
            X509Certificate cert = (X509Certificate) cf.generateCertificate(pem);

            assertTrue(crypto.validateCertificate(cert));
        } catch (CertificateException e) {
            Assert.fail("cannot read cert file");
        }
    }

    @Test
    public void testVerifyNullInput() {
        try {
            assertFalse(crypto.verify(null, null, null));
        } catch (CryptoException e) {
            fail("testVerifyNullInput should not have thrown exception. Error: " + e.getMessage());
        }
    } // testVerifyNullInput

    @Test(expected=CryptoException.class)
    public void testVerifyBadCert() throws CryptoException {
        byte[] badCert = new byte[] { (byte) 0x00 };
        crypto.verify(plainText, sig, badCert);
    } // testVerifyBadCert

    @Test(expected=CryptoException.class)
    public void testVerifyBadSig() throws CryptoException {
        byte[] badSig = new byte[] { (byte) 0x00 };
        crypto.verify(plainText, badSig, pemCert);
    } // testVerifyBadSign

    @Test
    public void testVerifyBadPlaintext() {
        byte[] badPlainText = new byte[] { (byte) 0x00 };
        try {
            assertFalse(crypto.verify(badPlainText, sig, pemCert));
        } catch (CryptoException e) {
            fail("testVerifyBadPlaintext should not have thrown exception. Error: " + e.getMessage());
        }
    } // testVerifyBadPlainText

    @Test
    public void testVerify() {
        try {
            assertTrue(crypto.verify(plainText, sig, pemCert));
        } catch (CryptoException e) {
            fail("testVerify should not have thrown exception. Error: " + e.getMessage());
        }
    } // testVerify

    @Test
    public void testSignNullKey() {
        try {
            crypto.sign(null, new byte[] { (byte) 0x00 });
            Assert.fail("sign() should have thrown an exception");
        } catch (CryptoException e) {
        }
    }

    @Test
    public void testSignNullData() {
        PrivateKey key;
        try {
            key = (PrivateKey) crypto.getTrustStore().getKey("key", "123456".toCharArray());
            crypto.sign(key, null);
            Assert.fail("sign() should have thrown an exception");
        } catch (UnrecoverableKeyException | KeyStoreException | NoSuchAlgorithmException e) {
            Assert.fail("Could not create private key. Error: " + e.getMessage());
        } catch (CryptoException e) {
        }
    }

    @Test
    @Ignore
    // TODO need to regen key now that we're using CryptoSuite
    public void testSign() {

        byte[] plainText = "123456".getBytes(UTF_8);
        byte[] signature;
        try {
            PrivateKey key = (PrivateKey) crypto.getTrustStore().getKey("key", "123456".toCharArray());
            signature = crypto.sign(key, plainText);

            BufferedInputStream bis = new BufferedInputStream(
                            this.getClass().getResourceAsStream("/keypair-signed.crt"));
            byte[] cert = IOUtils.toByteArray(bis);
            bis.close();

            assertTrue(crypto.verify(plainText, signature, cert));
        } catch (KeyStoreException | CryptoException | IOException | UnrecoverableKeyException
                        | NoSuchAlgorithmException e) {
            fail("Could not verify signature. Error: " + e.getMessage());
        }
    }
}
