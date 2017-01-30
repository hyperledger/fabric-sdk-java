package org.hyperledger.fabric.sdk;

import org.junit.Assert;
import org.junit.Test;

import java.net.MalformedURLException;

public class MemberServicesFabricCAImplTest {


    @Test
    public void testCOPCreation() {

        try {
            MemberServicesFabricCAImpl memberServices = new MemberServicesFabricCAImpl("http://localhost:99", null);
            Assert.assertNotNull(memberServices);
            Assert.assertSame(MemberServicesFabricCAImpl.class, memberServices.getClass());


        } catch (Exception e) {
            Assert.fail("Unexpected Exception " + e.getMessage());
        }
    }
    @Test
    public void testNullURL() {

        try {
             new MemberServicesFabricCAImpl(null, null);
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), MalformedURLException.class);

        }
    }
    @Test
    public void emptyURL() {

        try {
            new MemberServicesFabricCAImpl("", null);
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), MalformedURLException.class);

        }
    }

    @Test
    public void testBadProto() {

        try {
            new MemberServicesFabricCAImpl("file://localhost", null);
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), IllegalArgumentException.class);

        }
    }

    @Test
    public void testBadURLPath() {

        try {
            new MemberServicesFabricCAImpl("http://localhost/bad", null);
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), IllegalArgumentException.class);

        }
    }

    @Test
    public void testBadURLQuery() {

        try {
            new MemberServicesFabricCAImpl("http://localhost?bad", null);
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), IllegalArgumentException.class);

        }
    }


    @Test
    public void testBadEnrollUser() {

        try {
            MemberServicesFabricCAImpl memberServices = new MemberServicesFabricCAImpl("http://localhost:99", null);
            memberServices.enroll(null);
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), RuntimeException.class);

        }
    }

    @Test
    public void testBadEnrollBadUser() {

        try {
            MemberServicesFabricCAImpl memberServices = new MemberServicesFabricCAImpl("http://localhost:99", null);
            EnrollmentRequest req = new EnrollmentRequest();
            req.setEnrollmentID("");
            req.setEnrollmentSecret("adminpw");
            memberServices.enroll(null);
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), RuntimeException.class);

        }
    }

    @Test
    public void testBadEnrollBadSecret() {

        try {
            MemberServicesFabricCAImpl memberServices = new MemberServicesFabricCAImpl("http://localhost:99", null);
            EnrollmentRequest req = new EnrollmentRequest();
            req.setEnrollmentID("user");
            req.setEnrollmentSecret("");
            memberServices.enroll(null);
            Assert.fail("Expected exception");

        } catch (Exception e) {
            Assert.assertSame(e.getClass(), RuntimeException.class);

        }
    }
}
