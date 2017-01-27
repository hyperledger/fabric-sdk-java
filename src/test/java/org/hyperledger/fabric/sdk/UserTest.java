package org.hyperledger.fabric.sdk;

import org.hyperledger.fabric.sdk.exception.EnrollmentException;
import org.hyperledger.fabric.sdk.exception.RegistrationException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.net.MalformedURLException;
import java.security.cert.CertificateException;

public class UserTest {

    Chain testChain = null;

    @Before
    public void init() throws MalformedURLException {
        testChain = new Chain("chain1");
        try {
            MemberServices cop = new MemberServicesCOPImpl("http://localhost:8888", null);
            testChain.setMemberServices(cop);
            testChain.setKeyValStore(new FileKeyValStore(System.getProperty("user.home") + "/test.properties"));
            testChain.addPeer("grpc://localhost:7051", null);
            User registrar = testChain.getUser("admin");
            if (!registrar.isEnrolled()) {
                registrar = testChain.enroll("admin", "adminpw");
            }
            testChain.setRegistrar(registrar);

        } catch (CertificateException | EnrollmentException cex) {
            Assert.fail("Failed to initialize registrar");
        }

    }
    
    @Test
    public void testNoChain() {
    	try {
    		User user = new User("test", null);
    		Assert.fail("Should have failed as chain is null");
    	} catch(IllegalArgumentException ex) {}
    }
    
    //@Test
    public void testRegister() {
        RegistrationRequest req = createRegistrationRequest("testuser01", "bank_a");
        try {
            testChain.register(req);
        } catch (RegistrationException e) {
            Assert.fail("Registration of new user failed");
        }

        try {
            testChain.register(req);
            Assert.fail("Re-registration of a user should fail");
        } catch (RegistrationException e) {
        }
    }

    //@Test
    public void testIsRegister() {
        User user = testChain.getUser("testuser02");
        Assert.assertFalse(user.isRegistered());
        RegistrationRequest req = createRegistrationRequest(user.getName(), "bank_a");
        try {
            user.register(req);
        } catch (RegistrationException e) {
            Assert.fail("Registration of new user failed");
        }

        Assert.assertTrue(user.isRegistered());

        user = testChain.getUser("admin");
        Assert.assertTrue(user.isRegistered());
    }

    @Test
    public void testEnroll() {
        User user = testChain.getUser("testUser2");
        
        try {
            user.enroll("user2");
        } catch (EnrollmentException e) {
            Assert.fail("Enrollment failed");
        }

        try {
            user.enroll(user.getEnrollmentSecret());
            Assert.fail("Re-enrollment of a user should fail");
        } catch (EnrollmentException e) {
        }
    }

    @Test
    public void testIsEnrolled() {
        User user = testChain.getUser("testUser3");
        Assert.assertFalse(user.isEnrolled());
        
        try {
            user.enroll("user3");
        } catch (EnrollmentException e) {
            Assert.fail("Enrollment failed");
        }

        Assert.assertTrue(user.isEnrolled());

        user = testChain.getUser("admin");
        Assert.assertTrue(user.isEnrolled());
    }

    private RegistrationRequest createRegistrationRequest(String enrollmentId, String affiliationId) {
        RegistrationRequest req = new RegistrationRequest();
        req.setAffiliation(affiliationId);
        req.setEnrollmentID(enrollmentId);
        return req;
    }
}
