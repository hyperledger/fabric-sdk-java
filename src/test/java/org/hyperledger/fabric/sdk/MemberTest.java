package org.hyperledger.fabric.sdk;

import org.hyperledger.fabric.sdk.exception.EnrollmentException;
import org.hyperledger.fabric.sdk.exception.NoValidPeerException;
import org.hyperledger.fabric.sdk.exception.RegistrationException;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.security.cert.CertificateException;

public class MemberTest {

    Chain testChain = null;

    @Before
    public void init() {
        testChain = new Chain("chain1");
        try {
            testChain.setMemberServicesUrl("grpc://localhost:7054", null);
            testChain.setKeyValStore(new FileKeyValStore(System.getProperty("user.home") + "/test.properties"));
            testChain.addPeer("grpc://localhost:7051", null);
            Member registrar = testChain.getMember("admin");
            if (!registrar.isEnrolled()) {
                registrar = testChain.enroll("admin", "Xurw3yU9zI0l");
            }
            testChain.setRegistrar(registrar);

        } catch (CertificateException | EnrollmentException cex) {
            Assert.fail("Failed to initialize registrar");
        }

    }
    
    @Test
    public void testNoChain() {
    	try {
    		Member member = new Member("test", null);
    		Assert.fail("Should have failed as chain is null");
    	} catch(IllegalArgumentException ex) {}
    }
    
    @Test
    public void testNoPeers() {
    	try {
    		Chain testChain = new Chain("chain2");
    		Member member = new Member("test", testChain);
    		member.deploy(null);
    		Assert.fail("Should have failed as there are no peers");
    	} catch(NoValidPeerException ex) {
    	} catch(Exception ex) {
    		ex.printStackTrace();
    		Assert.fail("Expected NoValidPeerException, found "+ex.getClass().getName());
    	}
    	
    }

    @Test
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

    @Test
    public void testIsRegister() {
        Member member = testChain.getMember("testuser02");
        Assert.assertFalse(member.isRegistered());
        RegistrationRequest req = createRegistrationRequest(member.getName(), "bank_a");
        try {
            member.register(req);
        } catch (RegistrationException e) {
            Assert.fail("Registration of new user failed");
        }

        Assert.assertTrue(member.isRegistered());

        member = testChain.getMember("admin");
        Assert.assertTrue(member.isRegistered());
    }

    @Test
    public void testEnroll() {
        Member member = testChain.getMember("testuser03");
        RegistrationRequest req = createRegistrationRequest(member.getName(), "bank_a");
        try {
            member.register(req);
        } catch (RegistrationException e) {
            Assert.fail("Registration of new user failed");
        }


        try {
            member.enroll(member.getEnrollmentSecret());
        } catch (EnrollmentException e) {
            Assert.fail("Enrollment of new user failed");
        }

        try {
            member.enroll(member.getEnrollmentSecret());
            Assert.fail("Re-enrollment of a user should fail");
        } catch (EnrollmentException e) {
        }
    }

    @Test
    public void testIsEnrolled() {
        Member member = testChain.getMember("testuser04");
        Assert.assertFalse(member.isEnrolled());
        RegistrationRequest req = createRegistrationRequest(member.getName(), "bank_a");
        try {
            member.register(req);
        } catch (RegistrationException e) {
            Assert.fail("Registration of new user failed");
        }
        Assert.assertFalse(member.isEnrolled());
        try {
            member.enroll(member.getEnrollmentSecret());
        } catch (EnrollmentException e) {
            Assert.fail("Enrollment of new user failed");
        }

        Assert.assertTrue(member.isEnrolled());

        member = testChain.getMember("admin");
        Assert.assertTrue(member.isEnrolled());
    }

    private RegistrationRequest createRegistrationRequest(String enrollmentId, String affiliationId) {
        RegistrationRequest req = new RegistrationRequest();
        req.setAffiliation(affiliationId);
        req.setEnrollmentID(enrollmentId);
        return req;
    }
}
