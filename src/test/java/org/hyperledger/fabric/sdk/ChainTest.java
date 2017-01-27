package org.hyperledger.fabric.sdk;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.peer.FabricProposal.Proposal;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse.ProposalResponse;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.DeploymentException;
import org.hyperledger.fabric.sdk.exception.EnrollmentException;
import org.hyperledger.fabric.sdk.exception.NoValidOrdererException;
import org.hyperledger.fabric.sdk.exception.NoValidPeerException;
import org.hyperledger.fabric.sdk.helper.SDKUtil;
import org.hyperledger.fabric.sdk.transaction.DeployRequest;
import org.hyperledger.fabric.sdk.transaction.ProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.TransactionRequest;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

import com.google.protobuf.InvalidProtocolBufferException;

public class ChainTest {

	private static final Log logger = LogFactory.getLog(ChainTest.class);

	static Chain testChain = null;
	static String ccId = "myccgo-2";
	static String javaCcId = null;

	@BeforeClass
	public static void setupChain() {
		testChain = new Chain("**TEST_CHAINID**");
		try {
			testChain.setKeyValStore(new FileKeyValStore(System.getProperty("user.home")+"/test.properties"));
			testChain.addPeer("grpc://localhost:7051", null);
			testChain.addOrderer("grpc://localhost:7050", null);

			MemberServices cop = null;
			try {
				cop = new MemberServicesCOPImpl("http://localhost:8888", null);
				testChain.setMemberServices(cop);
				User user = getEnrolledMember("admin", "adminpw");
				testChain.newTransactionContext(user);
			} catch(Exception e) {
				logger.error("Failed to create COP object");
			}

			//testChain.setDevMode(true);
			ccId = deploy();
			javaCcId = deployJava();
			TimeUnit.SECONDS.sleep(15);// deployment takes time, so wait for it
			                           // to complete before making a query or
			                           // invoke call
		} catch (InterruptedException cex) {
			cex.printStackTrace();// TODO: Handle the exception properly
		}
	}

	private static String deployInternal(String path, String ccName, ArrayList<String> args, ChaincodeLanguage lang, String txId) throws DeploymentException {
		try {
			DeployRequest request = new DeployRequest();
			request.setChaincodePath(path);
			request.setArgs(args);
			request.setChaincodeName(ccName);
			request.setChaincodeLanguage(lang);
			request.setTxID(txId);

			Proposal proposal = testChain.createDeploymentProposal(request);

			List<ProposalResponse> responses = testChain.sendProposal(proposal);
			Assert.assertNotNull(responses);
			Assert.assertFalse(responses.isEmpty());
			ProposalResponse response = responses.get(0);
			Assert.assertNotNull(response);
			Assert.assertEquals(200, response.getResponse().getStatus()); // OK?
			List<TransactionResponse> tResponses = testChain.sendTransaction(proposal, responses);
			Assert.assertNotNull(tResponses);
			Assert.assertFalse(tResponses.isEmpty());
			Assert.assertEquals(TransactionResponse.Status.SUCCESS, tResponses.get(0).getStatus());

	//		return tResponses.get(0).getChainCodeID();
			return ccName;
	//		return txId;
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);// TODO: Handle the exception properly
		}
	}

	public static String deploy() throws DeploymentException {
		String ccName = "myccgo" + SDKUtil.generateUUID();
		return deployInternal("github.com/hyperledger/fabric/examples/chaincode/go/chaincode_example02",
		        ccName, new ArrayList<String>(Arrays.asList("init", "a", "700", "b", "2000")), ChaincodeLanguage.GO_LANG,
		        "mytx" + ccName);
	}

	public static String deployJava() {
		String ccName = "myccj" + SDKUtil.generateUUID();
		return deployInternal(System.getenv("GOPATH")+"/src/github.com/hyperledger/fabric/examples/chaincode/java/Example",
		        ccName, new ArrayList<String>(Arrays.asList("init", "a", "700", "b", "2000")), ChaincodeLanguage.JAVA,
		        "mytx" + ccName);
	}

@Test
    public void testCreateChain() {
	Chain myChain = null;
	try {
	    myChain = new Chain(null);
	    Assert.fail("Chain name should not be null");
	} catch (IllegalArgumentException exp) {
	}

	try {
	    myChain = new Chain("");
	    Assert.fail("Chain name should not be empty");
	} catch (IllegalArgumentException exp) {
	}

	myChain = new Chain("mychain");
    }

    @Test
    public void testCreateTransactionProposal() throws EnrollmentException {
	TransactionRequest request = new TransactionRequest();
	request.setArgs(new ArrayList<>(Arrays.asList("query", "a")));
	User admin = getEnrolledMember("admin", "adminpw");

	Chain myChain = new Chain("mychain");
	myChain.newTransactionContext(admin);

	try {
	    myChain.createTransactionProposal(null);
	    Assert.fail("Should not create proposal because request is null");
	} catch (IllegalArgumentException exp) {
	}

	try {
	    myChain.createTransactionProposal(request);
	    Assert.fail("Should not create proposal because chaincode name is missing");
	} catch (IllegalArgumentException exp) {
	}

	request.setChaincodeName("mychaincodename");
	myChain.createTransactionProposal(request);

	Chain myChain2 = new Chain("mychain");
	try {
	    myChain2.createTransactionProposal(request);
	    Assert.fail("Should not create proposal because transaction context is missing");
	} catch (IllegalArgumentException exp) {
	}

    }

    @Test
    public void testCreateDeploymentProposal() throws EnrollmentException {
	ArrayList<String> args = new ArrayList<String>(Arrays.asList("init", "a", "700", "b", "2000"));
	DeployRequest request = new DeployRequest();
	request.setArgs(args);

	request.setChaincodeLanguage(ChaincodeLanguage.GO_LANG);
	request.setTxID("txId");
	User admin = getEnrolledMember("admin", "adminpw");

	Chain myChain = new Chain("mychain");
	myChain.newTransactionContext(admin);

	try {
	    myChain.createDeploymentProposal(null);
	    Assert.fail("Should not create proposal because request is null");
	} catch (IllegalArgumentException exp) {
	}

	try {
	    myChain.createDeploymentProposal(request);
	    Assert.fail("Should not create proposal because chaincode name is missing");
	} catch (IllegalArgumentException exp) {
	}

	request.setChaincodeName("mychaincodename");

	try {
	    myChain.createDeploymentProposal(request);
	    Assert.fail("Should not create proposal because chaincode path is missing");
	} catch (IllegalArgumentException exp) {
	}

	request.setChaincodePath("github.com/hyperledger/fabric/examples/chaincode/go/chaincode_example02");
	myChain.createDeploymentProposal(request);

	Chain myChain2 = new Chain("mychain");
	try {
	    myChain2.createDeploymentProposal(request);
	    Assert.fail("Should not create proposal because transaction context is missing");
	} catch (IllegalArgumentException exp) {
	}

    }

    @Test
    public void testSendProposal() throws EnrollmentException {
	User admin = getEnrolledMember("admin", "adminpw");
	Chain myChain = new Chain("mychain");

	try {
	    myChain.sendProposal(null);
	    Assert.fail("Should not send proposal without valid peers");
	} catch (NoValidPeerException exp) {
	}

	myChain.addPeer("grpc://wrongpeer:7051", null);
	try {
	    myChain.sendProposal(null);
	    Assert.fail("Should fail without transaction context");
	} catch (IllegalArgumentException exp) {
	}
	myChain.newTransactionContext(admin);

	try {
	    myChain.sendProposal(null);
	    Assert.fail("Should fail because proposal is null");
	} catch (IllegalArgumentException exp) {
	}

	try {
	    myChain.sendProposal(ProposalBuilder.newBuilder().build());
	    Assert.fail("Should fail because peer is invalid");
	} catch (Exception exp) {
	    if (exp instanceof IllegalArgumentException) {
		Assert.fail("Should not have thrown a validation exception");
	    }
	}

    }

    @Test
    public void testSendTransaction() throws EnrollmentException, InvalidProtocolBufferException, CryptoException {
	User admin = getEnrolledMember("admin", "adminpw");
	Chain myChain = new Chain("mychain");
	ProposalResponse response = ProposalResponse.newBuilder().build();
	List<ProposalResponse> responses = new ArrayList<ProposalResponse>();
	responses.add(response);
	List<ProposalResponse> emptyResponses = new ArrayList<ProposalResponse>();

	TransactionRequest request = new TransactionRequest();
	request.setArgs(new ArrayList<>(Arrays.asList("query", "a")));
	request.setChaincodeName("mychaincode");
	Proposal proposal = testChain.createTransactionProposal(request);

	try {
	    myChain.sendTransaction(null, null);
	    Assert.fail("Should fail because proposal and endorsements are null");
	} catch (IllegalArgumentException exp) {
	}

	try {
	    myChain.sendTransaction(proposal, null);
	    Assert.fail("Should fail because endorsements are null");
	} catch (IllegalArgumentException exp) {
	}

	try {
	    myChain.sendTransaction(proposal, emptyResponses);
	    Assert.fail("Should fail because endorsements are empty");
	} catch (IllegalArgumentException exp) {
	}

	try {
	    myChain.sendTransaction(null, responses);
	    Assert.fail("Should fail because proposal is null");
	} catch (IllegalArgumentException exp) {
	}

	try {
	    myChain.sendTransaction(proposal, responses);
	    Assert.fail("Should fail without transaction context");
	} catch (IllegalArgumentException exp) {
	}
	myChain.newTransactionContext(admin);

	try {
	    myChain.sendTransaction(proposal, responses);
	    Assert.fail("Should not send proposal without valid orderers");
	} catch (NoValidOrdererException exp) {
	}

	myChain.addOrderer("grpc://wrongpeer:7051", null);

	try {
	    myChain.sendTransaction(proposal, responses);
	    Assert.fail("Should fail because orderer is invalid");
	} catch (Exception exp) {
	    if (exp instanceof IllegalArgumentException) {
		Assert.fail("Should not have thrown a validation exception");
	    }
	}

    }


	@Test
	public void testQuery() throws EnrollmentException {

		TransactionRequest request = new TransactionRequest();
		request.setArgs(new ArrayList<>(Arrays.asList("query", "a")));
		request.setChaincodeName(ccId);
		Proposal proposal = testChain.createTransactionProposal(request);
		List<ProposalResponse> responses = testChain.sendProposal(proposal);
		Assert.assertNotNull(responses);
		Assert.assertFalse(responses.isEmpty());
		ProposalResponse response = responses.get(0);
		Assert.assertNotNull(response);
		Assert.assertEquals(200, response.getResponse().getStatus());
		Assert.assertEquals("700", response.getResponse().getPayload().toStringUtf8());

	}

	@Test
	public void testQueryJava() throws EnrollmentException {
		TransactionRequest request = new TransactionRequest();
		request.setArgs(new ArrayList<>(Arrays.asList("query", "a")));
		request.setChaincodeName(javaCcId);
		request.setChaincodeLanguage(ChaincodeLanguage.JAVA);
		Proposal proposal = testChain.createTransactionProposal(request);
		List<ProposalResponse> responses = testChain.sendProposal(proposal);
		Assert.assertNotNull(responses);
		Assert.assertFalse(responses.isEmpty());
		ProposalResponse response = responses.get(0);
		Assert.assertNotNull(response);
		Assert.assertEquals(200, response.getResponse().getStatus());

		Assert.assertEquals("700", response.getResponse().getPayload().toString());
	}

	@Test
	public void testInvoke() {
		try {
			TransactionRequest request = new TransactionRequest();
			request.setArgs(new ArrayList<>(Arrays.asList("invoke", "a", "b", "200")));
			request.setChaincodeName(ccId);
			Proposal proposal = testChain.createTransactionProposal(request);
			List<ProposalResponse> responses = testChain.sendProposal(proposal);
			Assert.assertNotNull(responses);
			Assert.assertFalse(responses.isEmpty());
			ProposalResponse response = responses.get(0);
			Assert.assertNotNull(response);
			Assert.assertEquals(200, response.getResponse().getStatus());
			List<TransactionResponse> transactions = testChain.sendTransaction(proposal, responses);
			Assert.assertNotNull(transactions);
			Assert.assertFalse(transactions.isEmpty());
			TransactionResponse tresponse = transactions.get(0);
			Assert.assertNotNull(tresponse);
			Assert.assertEquals(TransactionResponse.Status.SUCCESS, tresponse.getStatus());
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);// TODO: Handle the exception properly
		}
	}

	/*@Test
	public void testInvokeJava() {
		TransactionRequest request = new TransactionRequest();
		request.setArgs(new ArrayList<>(Arrays.asList("invoke", "a", "b", "200")));
		request.setChaincodeName(javaCcId);
		Proposal proposal = testChain.createTransactionProposal(request);
		List<ProposalResponse> responses = testChain.sendProposal(null);
		Assert.assertNotNull(responses);
		Assert.assertFalse(responses.isEmpty());
		ProposalResponse response = responses.get(0);
		Assert.assertNotNull(response);
		Assert.assertEquals(TransactionResponse.Status.SUCCESS, response.getResponse().getStatus());
	}*/

    public static User getEnrolledMember(String userId, String secret) throws EnrollmentException {
	User user = testChain.getUser(userId);
		if (!user.isEnrolled()) {
	    user = testChain.enroll(userId, secret);
		}
		return user;
	}
}
