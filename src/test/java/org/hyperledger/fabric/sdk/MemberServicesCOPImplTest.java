package org.hyperledger.fabric.sdk;

import org.junit.Assert;
import org.junit.Test;

import java.net.MalformedURLException;

public class MemberServicesCOPImplTest {


    @Test
    public void testCOPCreation() {

        try {
            MemberServicesCOPImpl cop = new MemberServicesCOPImpl("http://localhost:99", null);
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
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), MalformedURLException.class);

        }
    }
    @Test
    public void emptyURL() {

        try {
            new MemberServicesCOPImpl("", null);
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), MalformedURLException.class);

        }
    }

    @Test
    public void testBadProto() {

        try {
            new MemberServicesCOPImpl("file://localhost", null);
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), IllegalArgumentException.class);

        }
    }

    @Test
    public void testBadURLPath() {

        try {
            new MemberServicesCOPImpl("http://localhost/bad", null);
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), IllegalArgumentException.class);

        }
    }

    @Test
    public void testBadURLQuery() {

        try {
            new MemberServicesCOPImpl("http://localhost?bad", null);
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), IllegalArgumentException.class);

        }
    }


    @Test
    public void testBadEnrollUser() {

        try {
            MemberServicesCOPImpl cop = new MemberServicesCOPImpl("http://localhost:99", null);
            cop.enroll(null);
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), RuntimeException.class);

        }
    }

    @Test
    public void testBadEnrollBadUser() {

        try {
            MemberServicesCOPImpl cop = new MemberServicesCOPImpl("http://localhost:99", null);
            EnrollmentRequest req = new EnrollmentRequest();
            req.setEnrollmentID("");
            req.setEnrollmentSecret("adminpw");
            cop.enroll(null);
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), RuntimeException.class);

        }
    }

    @Test
    public void testBadEnrollBadSecret() {

        try {
            MemberServicesCOPImpl cop = new MemberServicesCOPImpl("http://localhost:99", null);
            EnrollmentRequest req = new EnrollmentRequest();
            req.setEnrollmentID("user");
            req.setEnrollmentSecret("");
            cop.enroll(null);
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), RuntimeException.class);

        }
    }
}
