package org.hyperledger.fabric.sdk;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.peer.FabricProposal.Proposal;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse.ProposalResponse;
import org.hyperledger.fabric.sdk.exception.DeploymentException;
import org.hyperledger.fabric.sdk.exception.EnrollmentException;
import org.hyperledger.fabric.sdk.helper.SDKUtil;
import org.hyperledger.fabric.sdk.transaction.DeployRequest;
import org.hyperledger.fabric.sdk.transaction.TransactionRequest;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

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
			} catch(Exception e) {
				logger.error("Failed to create COP object");
			}

			//testChain.setDevMode(true);
			ccId = deploy();
			// javaCcId = deployJava();
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

			Member admin = getEnrolledMember("admin", "adminpw");

			Proposal proposal = testChain.createDeploymentProposal(admin, request);

			List<ProposalResponse> responses = testChain.sendProposal(admin, proposal);
			Assert.assertNotNull(responses);
			Assert.assertFalse(responses.isEmpty());
			ProposalResponse response = responses.get(0);
			Assert.assertNotNull(response);
			Assert.assertEquals(200, response.getResponse().getStatus()); // OK?
			List<TransactionResponse> tResponses = testChain.sendTransaction(admin, proposal, responses);
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
		        ccName, new ArrayList<>(Arrays.asList("init", "a", "700", "b", "2000")), ChaincodeLanguage.GO_LANG,
		        "mytx" + ccName);
	}

	public static String deployJava() {
		return deployInternal(System.getenv("GOPATH")+"/src/github.com/hyperledger/fabric/examples/chaincode/java/Example",
		        "myccj", new ArrayList<>(Arrays.asList("init", "a", "700", "b", "2000")), ChaincodeLanguage.JAVA,
		        "mytxjava");
	}


	@Test
	public void testQuery() throws EnrollmentException {

		TransactionRequest request = new TransactionRequest();
		request.setArgs(new ArrayList<>(Arrays.asList("query", "a")));
		request.setChaincodeName(ccId);
		Member admin = getEnrolledMember("admin", "adminpw");
		Proposal proposal = testChain.createTransactionProposal(admin,request);
		List<ProposalResponse> responses = testChain.sendProposal(admin, proposal);
		Assert.assertNotNull(responses);
		Assert.assertFalse(responses.isEmpty());
		ProposalResponse response = responses.get(0);
		Assert.assertNotNull(response);
		Assert.assertEquals(200, response.getResponse().getStatus());
		Assert.assertEquals("700", response.getResponse().getPayload().toStringUtf8());

	}

	/*@Test
	public void testQueryJava() {
		TransactionRequest request = new TransactionRequest();
		request.setArgs(new ArrayList<>(Arrays.asList("query", "a")));
		request.setChaincodeName(javaCcId);
		request.setChaincodeLanguage(ChaincodeLanguage.JAVA);
		Proposal proposal = testChain.createTransactionProposal(request);
		List<ProposalResponse> responses = testChain.sendProposal(null);
		Assert.assertNotNull(responses);
		Assert.assertFalse(responses.isEmpty());
		ProposalResponse response = responses.get(0);
		Assert.assertNotNull(response);
		Assert.assertEquals(TransactionResponse.Status.SUCCESS, response.getResponse().getStatus());
		System.out.println("Queried:"+response.getResponse().getPayload().toString());
		Assert.assertEquals("700", response.getResponse().getPayload().toString());
	}*/

	@Test
	public void testInvoke() {
		try {
			Member admin = getEnrolledMember("admin", "adminpw");
			TransactionRequest request = new TransactionRequest();
			request.setArgs(new ArrayList<>(Arrays.asList("invoke", "a", "b", "200")));
			request.setChaincodeName(ccId);
			Proposal proposal = testChain.createTransactionProposal(admin, request);
			List<ProposalResponse> responses = testChain.sendProposal(admin, proposal);
			Assert.assertNotNull(responses);
			Assert.assertFalse(responses.isEmpty());
			ProposalResponse response = responses.get(0);
			Assert.assertNotNull(response);
			Assert.assertEquals(200, response.getResponse().getStatus());
			List<TransactionResponse> transactions = testChain.sendTransaction(admin, proposal, responses);
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

	public static Member getEnrolledMember(String user, String secret) throws EnrollmentException {
		Member member = testChain.getMember("admin");
		if (!member.isEnrolled()) {
			member = testChain.enroll(user, secret);
		}
		return member;
	}
}
