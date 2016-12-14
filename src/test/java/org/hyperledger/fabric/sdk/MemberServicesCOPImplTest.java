package org.hyperledger.fabric.sdk;

import org.junit.Assert;
import org.junit.Test;

import java.net.MalformedURLException;
import java.security.cert.CertificateException;

public class MemberServicesCOPImplTest {


    @Test
    public void testCOPCreation() {

        try {
            MemberServices cop = newCop("http://localhost:99");
            Assert.assertNotNull(cop);
            Assert.assertSame(MemberServicesCOPImpl.class, cop.getClass());


        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }
    @Test
    public void testNullURL() {

        try {
             new MemberServicesCOPImpl(null, null);
            MemberServices cop = newCop(null);
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), IllegalArgumentException.class);

        }
    }
    @Test
    public void emptyURL() {

        try {

            MemberServices cop = newCop("");
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), IllegalArgumentException.class);

        }
    }

    @Test
    public void testBadProto() {

        try {

            MemberServices cop = newCop("file://localhost");

            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), IllegalArgumentException.class);

        }
    }

    @Test
    public void testBadURLPath() {

        try {

            MemberServices cop = newCop("http://localhost/bad");
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), IllegalArgumentException.class);

        }
    }

    @Test
    public void testBadURLQuery() {

        try {

            MemberServices cop = newCop("http://localhost?bad");

            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), IllegalArgumentException.class);

        }
    }


    @Test
    public void testBadEnrollUser() {

        try {
            MemberServices cop = newCop("http://localhost:99");
            cop.enroll(null);
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), org.hyperledger.fabric.sdk.exception.EnrollmentException.class);

        }
    }

    @Test
    public void testBadEnrollBadUser() {

        try {

            MemberServices cop = newCop("http://localhost:99");

            EnrollmentRequest req = new EnrollmentRequest();
            req.setEnrollmentID("");
            req.setEnrollmentSecret("adminpw");
            cop.enroll(req);
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), org.hyperledger.fabric.sdk.exception.EnrollmentException.class);

        }
    }

    @Test
    public void testBadEnrollBadSecret() {

        try {

            MemberServices cop = newCop("http://localhost:99");
            EnrollmentRequest req = new EnrollmentRequest();
            req.setEnrollmentID("user");
            req.setEnrollmentSecret("");
            cop.enroll(req);
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), org.hyperledger.fabric.sdk.exception.EnrollmentException.class);

        }
    }

    @Test
    public void testAdminEnrollTest() { //Requires active COP server

        try {

            MemberServices cop = newCop("http://localhost:8888");
            EnrollmentRequest req = new EnrollmentRequest();
            req.setEnrollmentID("admin");//"admin", "adminpw"
            req.setEnrollmentSecret("adminpw");
            Enrollment enrollment = cop.enroll(req);


            Assert.assertNotNull(enrollment);


            String privateKey = enrollment.getKey();
            Assert.assertNotNull(privateKey);
            Assert.assertTrue("Key is string with length greater than 1", privateKey.length() >1);

            String certificate = enrollment.getCert();
            Assert.assertNotNull(certificate);
            Assert.assertTrue("Certificate is string with length greater than 1", certificate.length() >1);



        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());

        }
    }

    private static  MemberServices  newCop(String url) throws CertificateException, MalformedURLException {

        return new MemberServicesCOPImpl(url, null);

    }
}
