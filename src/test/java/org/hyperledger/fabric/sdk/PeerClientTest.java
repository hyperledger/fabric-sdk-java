package org.hyperledger.fabric.sdk;

import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;

import org.hyperledger.fabric.sdk.exception.EnrollmentException;
import org.hyperledger.fabric.sdk.exception.RegistrationException;
import org.junit.Before;
import org.junit.Test;

public class PeerClientTest {

	Chain testChain = null;

	@Before
	public void init() {
		testChain = new Chain("chain1");
		try {
			testChain.setMemberServicesUrl("grpc://localhost:7054", null);
			testChain.setKeyValStore(new FileKeyValStore(System.getProperty("user.home")+"/test.properties"));
			testChain.addPeer("grpc://localhost:7051", null);
			Member registrar = testChain.getMember("admin");
			if (!registrar.isEnrolled()) {
				registrar = testChain.enroll("admin", "Xurw3yU9zI0l");
			}
			testChain.setRegistrar(registrar);

			deploy();
		} catch(CertificateException | RegistrationException | EnrollmentException cex) {
			cex.printStackTrace();// TODO: Handle the exception properly
		}

	}

	public void deploy() throws RegistrationException, EnrollmentException {
		DeployRequest request = new DeployRequest();
		request.setChaincodePath("github.com/hyperledger/fabric/examples/chaincode/go/chaincode_example02");
		request.setArgs(new ArrayList<>(Arrays.asList("init", "a", "100", "b", "20000")));

		Member member = getMember("User1", "bank_a");
		member.deploy(request);
	}

	@Test
	public void testQuery() throws RegistrationException, EnrollmentException {

		QueryRequest request = new QueryRequest();
		request.setArgs(new ArrayList<>(Arrays.asList("query", "a")));
		Member member = getMember("User1", "bank_a");
		member.query(request);

	}

	@Test
	public void testInvoke() throws RegistrationException, EnrollmentException {

		InvokeRequest request = new InvokeRequest();
		request.setArgs(new ArrayList<>(Arrays.asList("invoke", "a", "b", "200")));

		Member member = getMember("User1", "bank_a");
		member.invoke(request);

	}

	private Member getMember(String enrollmentId, String affiliation) throws RegistrationException, EnrollmentException {
		Member member = testChain.getMember(enrollmentId);
		if (!member.isRegistered()) {
			RegistrationRequest registrationRequest = new RegistrationRequest();
			registrationRequest.setEnrollmentID(enrollmentId);
			registrationRequest.setAffiliation(affiliation);
//			registrationRequest.setAccount(); TODO setAccount missing from registrationRequest?
			member = testChain.registerAndEnroll(registrationRequest);
		} else if (!member.isEnrolled()) {
			member = testChain.enroll(enrollmentId, member.getEnrollmentSecret());
		}
		return member;
	}
}
