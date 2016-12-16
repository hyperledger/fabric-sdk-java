package org.hyperledger.fabric.sdk;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.TimeUnit;

import com.google.protobuf.InvalidProtocolBufferException;
import org.hyperledger.fabric.protos.peer.FabricProposal.Proposal;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse.ProposalResponse;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.DeploymentException;
import org.hyperledger.fabric.sdk.transaction.DeployRequest;
import org.hyperledger.fabric.sdk.transaction.TransactionRequest;
import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class ChainTest {

	static Chain testChain = null;
	static String ccId = null;
	static String javaCcId = null;

	@BeforeClass
	public static void setupChain() {
		testChain = new Chain("chain1");
		try {
//			testChain.setMemberServicesUrl("grpc://localhost:7054", null);
			testChain.setKeyValStore(new FileKeyValStore(System.getProperty("user.home")+"/test.properties"));
			testChain.addPeer("grpc://localhost:7051", null);
			testChain.addOrderer("grpc://localhost:5151", null);
			//testChain.setDevMode(true);
			ccId = deploy();
			javaCcId = deployJava();
			TimeUnit.SECONDS.sleep(10);// deployment takes time, so wait for it to complete before making a query or invoke call
		} catch(InterruptedException cex) {
			cex.printStackTrace();// TODO: Handle the exception properly
		}
	}
	
	private static String deployInternal(String path, String ccName, ArrayList<String> args, ChaincodeLanguage lang) throws DeploymentException {
		try {
			DeployRequest request = new DeployRequest();
			request.setChaincodePath(path);
			request.setArgs(args);
			request.setChaincodeName(ccName);
			request.setChaincodeLanguage(lang);
			Proposal proposal = testChain.createDeploymentProposal(request);
			List<ProposalResponse> responses = testChain.sendProposal(proposal);
			Assert.assertNotNull(responses);
			Assert.assertFalse(responses.isEmpty());
			ProposalResponse response = responses.get(0);
			Assert.assertNotNull(response);
			Assert.assertEquals(TransactionResponse.Status.SUCCESS, response.getResponse().getStatus()); // OK?
			List<TransactionResponse> tResponses = testChain.sendTransaction(proposal, responses);
			Assert.assertNotNull(tResponses);
			Assert.assertFalse(tResponses.isEmpty());
			Assert.assertEquals(TransactionResponse.Status.SUCCESS, tResponses.get(0).getStatus());
			return tResponses.get(0).getChainCodeID();
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);// TODO: Handle the exception properly
		}
	}

	public static String deploy() throws DeploymentException {
		return deployInternal("github.com/hyperledger/fabric/examples/chaincode/go/chaincode_example02",
				"mycc", new ArrayList<>(Arrays.asList("init", "a", "700", "b", "20000")), ChaincodeLanguage.GO_LANG);		
	}

	public static String deployJava() {
		return deployInternal(System.getenv("GOPATH")+"/src/github.com/hyperledger/fabric/examples/chaincode/java/Example",
				"myccj", new ArrayList<>(Arrays.asList("init", "a", "700", "b", "20000")), ChaincodeLanguage.JAVA);	
	}
	
	
	@Test
	public void testQuery() {		
		TransactionRequest request = new TransactionRequest();
		request.setArgs(new ArrayList<>(Arrays.asList("query", "a")));
		request.setChaincodeName(ccId);
		Proposal proposal = testChain.createTransactionProposal(request);
		List<ProposalResponse> responses = testChain.sendProposal(proposal);
		Assert.assertNotNull(responses);
		Assert.assertFalse(responses.isEmpty());
		ProposalResponse response = responses.get(0);
		Assert.assertNotNull(response);
		Assert.assertEquals(TransactionResponse.Status.SUCCESS, response.getResponse().getStatus());
		Assert.assertEquals("700", response.getResponse().getPayload().toString());
	}
	
	@Test
	public void testQueryJava() {
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
		Assert.assertEquals(TransactionResponse.Status.SUCCESS, response.getResponse().getStatus());
		Assert.assertEquals("700", response.getResponse().getPayload().toString());
	}

	@Test
	public void testInvoke() {
		TransactionRequest request = new TransactionRequest();
		request.setArgs(new ArrayList<>(Arrays.asList("invoke", "a", "b", "200")));
		request.setChaincodeName(ccId);
		Proposal proposal = testChain.createTransactionProposal(request);
		List<ProposalResponse> responses = testChain.sendProposal(proposal);
		Assert.assertNotNull(responses);
		Assert.assertFalse(responses.isEmpty());
		ProposalResponse response = responses.get(0);
		Assert.assertNotNull(response);
		Assert.assertEquals(TransactionResponse.Status.SUCCESS, response.getResponse().getStatus());		
	}

	@Test
	public void testInvokeJava() {
		TransactionRequest request = new TransactionRequest();
		request.setArgs(new ArrayList<>(Arrays.asList("invoke", "a", "b", "200")));
		request.setChaincodeName(javaCcId);
		Proposal proposal = testChain.createTransactionProposal(request);
		List<ProposalResponse> responses = testChain.sendProposal(proposal);
		Assert.assertNotNull(responses);
		Assert.assertFalse(responses.isEmpty());
		ProposalResponse response = responses.get(0);
		Assert.assertNotNull(response);
		Assert.assertEquals(TransactionResponse.Status.SUCCESS, response.getResponse().getStatus());
	}

}
