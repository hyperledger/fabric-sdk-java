package org.hyperledger.fabric.sdk;

//import java.security.cert.CertificateException;
//import java.util.ArrayList;
//import java.util.Arrays;
//import java.util.concurrent.TimeUnit;
//
//import org.hyperledger.fabric.sdk.exception.ChainCodeException;
//import org.hyperledger.fabric.sdk.exception.DeploymentException;
//import org.hyperledger.fabric.sdk.exception.EnrollmentException;
//import org.hyperledger.fabric.sdk.exception.RegistrationException;
//import org.junit.BeforeClass;
//import org.junit.Test;

public class PeerClientTest {

//	static Chain testChain = null;
//	static ChainCodeResponse deployResponse = null;
//	static ChainCodeResponse javaDeployResponse = null;
//
//	@BeforeClass
//	public static void setupChain() {
//		testChain = new Chain("chain1");
//		try {
//			testChain.setMemberServicesUrl("grpc://localhost:7054", null);
//			testChain.setKeyValStore(new FileKeyValStore(System.getProperty("user.home")+"/test.properties"));
//			testChain.addPeer("grpc://localhost:7051", null);
//			//testChain.setDevMode(true);
//			User registrar = testChain.getUser("admin");
//			if (!registrar.isEnrolled()) {
//				registrar = testChain.enroll("admin", "Xurw3yU9zI0l");
//			}
//			testChain.setRegistrar(registrar);
//			deployResponse = deploy();
//			javaDeployResponse = deployJava();
//			TimeUnit.SECONDS.sleep(10);// deployment takes time, so wait for it to complete before making a query or invoke call
//		} catch(CertificateException | RegistrationException | EnrollmentException | InterruptedException cex) {
//			cex.printStackTrace();// TODO: Handle the exception properly
//		}
//	}
//
//
//	public static ChainCodeResponse deploy() throws RegistrationException, EnrollmentException, DeploymentException {
//		DeploymentProposalRequest request = new DeploymentProposalRequest();
//		request.setChaincodePath("github.com/hyperledger/fabric/examples/chaincode/go/chaincode_example02");
//		request.setArgs(new ArrayList<>(Arrays.asList("init", "a", "700", "b", "20000")));
//		User user = getUser("User1", "bank_a");
//		request.setChaincodeName("mycc");
//		request.setChaincodeLanguage(ChaincodeLanguage.GO_LANG);
//		return user.deploy(request);
//	}
//
//	public static ChainCodeResponse deployJava() throws RegistrationException, EnrollmentException {
//		DeploymentProposalRequest request = new DeploymentProposalRequest();
//		request.setChaincodePath(System.getenv("GOPATH")+"/src/github.com/hyperledger/fabric/examples/chaincode/java/Example");
//		request.setArgs(new ArrayList<>(Arrays.asList("init", "a", "700", "b", "20000")));
//		User user = getUser("User1", "bank_a");
//		request.setChaincodeName("myccj");
//		request.setChaincodeLanguage(ChaincodeLanguage.JAVA);
//		return user.deploy(request);
//
//	}
//
//	@Test
//	public void testQuery() throws RegistrationException, EnrollmentException, ChainCodeException {
//		testInvoke(); // the amount is stored
//		QueryRequest request = new QueryRequest();
//		request.setArgs(new ArrayList<>(Arrays.asList("query", "a")));
//		request.setChaincodeID(deployResponse.getChainCodeID());
//		request.setChaincodeName(deployResponse.getChainCodeID());
//		User user = getUser("User1", "bank_a");
//		user.query(request);
//	}
//
//	@Test
//	public void testInvoke() throws RegistrationException, EnrollmentException, ChainCodeException {
//		InvokeRequest request = new InvokeRequest();
//		request.setArgs(new ArrayList<>(Arrays.asList("invoke", "a", "b", "200")));
//		request.setChaincodeID(deployResponse.getChainCodeID());
//		request.setChaincodeName(deployResponse.getChainCodeID());
//		User user = getUser("User1", "bank_a");
//		user.invoke(request);
//	}
//
//	@Test
//	public void testQueryJava() throws RegistrationException, EnrollmentException, ChainCodeException {
//		testInvokeJava();
//		QueryRequest request = new QueryRequest();
//		request.setArgs(new ArrayList<>(Arrays.asList("query", "a")));
//		request.setChaincodeID(javaDeployResponse.getChainCodeID());
//		request.setChaincodeName(javaDeployResponse.getChainCodeID());
//		request.setChaincodeLanguage(ChaincodeLanguage.JAVA);
//		User user = getUser("User1", "bank_a");
//		user.query(request);
//	}
//
//	@Test
//	public void testInvokeJava() throws RegistrationException, EnrollmentException, ChainCodeException {
//		InvokeRequest request = new InvokeRequest();
//		request.setArgs(new ArrayList<>(Arrays.asList("invoke", "a", "b", "200")));
//		request.setChaincodeID(javaDeployResponse.getChainCodeID());
//		request.setChaincodeName(javaDeployResponse.getChainCodeID());
//		request.setChaincodeLanguage(ChaincodeLanguage.JAVA);
//		User user = getUser("User1", "bank_a");
//		user.invoke(request);
//	}
//
//	private static User getUser(String enrollmentId, String affiliation) throws RegistrationException, EnrollmentException {
//		User user = testChain.getUser(enrollmentId);
//		if (!user.isRegistered()) {
//			RegistrationRequest registrationRequest = new RegistrationRequest();
//			registrationRequest.setEnrollmentID(enrollmentId);
//			registrationRequest.setAffiliation(affiliation);
//			//registrationRequest.setAccount(); TODO setAccount missing from registrationRequest?
//			user = testChain.registerAndEnroll(registrationRequest);
//		} else if (!user.isEnrolled()) {
//			user = testChain.enroll(enrollmentId, user.getEnrollmentSecret());
//		}
//		return user;
//	}
}
