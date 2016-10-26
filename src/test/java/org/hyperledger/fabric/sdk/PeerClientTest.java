package org.hyperledger.fabric.sdk;

import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;

import org.hyperledger.fabric.sdk.exception.ChainCodeException;
import org.hyperledger.fabric.sdk.exception.DeploymentException;
import org.hyperledger.fabric.sdk.exception.EnrollmentException;
import org.hyperledger.fabric.sdk.exception.RegistrationException;
import org.junit.BeforeClass;
import org.junit.Test;

public class PeerClientTest {

	static Chain testChain = null;
	static ChainCodeResponse deployResponse = null;
	
	@BeforeClass
	public static void setupChain() {
		testChain = new Chain("chain1");
		try {
			testChain.setMemberServicesUrl("grpc://localhost:7054", null);
			testChain.setKeyValStore(new FileKeyValStore(System.getProperty("user.home")+"/test.properties"));
			testChain.addPeer("grpc://localhost:7051", null);
//			testChain.setDevMode(true);
			Member registrar = testChain.getMember("admin");
			if (!registrar.isEnrolled()) {
				registrar = testChain.enroll("admin", "Xurw3yU9zI0l");
			}
			testChain.setRegistrar(registrar);
			deployResponse = deploy();
			Thread.sleep(2*1000);// deployment takes time, so wait for it to complete before making a query or invoke call
		} catch(CertificateException | RegistrationException | EnrollmentException | InterruptedException cex) {
			cex.printStackTrace();// TODO: Handle the exception properly
		}
	}
		
	
	public static ChainCodeResponse deploy() throws RegistrationException, EnrollmentException, DeploymentException {
		DeployRequest request = new DeployRequest();
		request.setChaincodePath("github.com/hyperledger/fabric/examples/chaincode/go/chaincode_example02");
		request.setArgs(new ArrayList<>(Arrays.asList("init", "a", "700", "b", "20000")));
		Member member = getMember("User1", "bank_a");
		request.setChaincodeName("mycc");
		return member.deploy(request);
	}
	
	@Test
	public void testQuery() throws RegistrationException, EnrollmentException, ChainCodeException {
		QueryRequest request = new QueryRequest();
		request.setArgs(new ArrayList<>(Arrays.asList("query", "a")));
		request.setChaincodeID(deployResponse.getChainCodeID());
		request.setChaincodeName(deployResponse.getChainCodeID());
		Member member = getMember("User1", "bank_a");
		member.query(request);
		
				
	} 

	@Test
	public void testInvoke() throws RegistrationException, EnrollmentException, ChainCodeException {
		InvokeRequest request = new InvokeRequest();
		request.setArgs(new ArrayList<>(Arrays.asList("invoke", "a", "b", "200")));
		request.setChaincodeID(deployResponse.getChainCodeID());
		request.setChaincodeName(deployResponse.getChainCodeID());
		Member member = getMember("User1", "bank_a");
		member.invoke(request);		
	}
	
	private static Member getMember(String enrollmentId, String affiliation) throws RegistrationException, EnrollmentException {
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
