/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 * 	  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk;

import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.protobuf.InvalidProtocolBufferException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.peer.ChaincodeProposal;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.EnrollmentException;
import org.hyperledger.fabric.sdk.exception.NoValidOrdererException;
import org.hyperledger.fabric.sdk.exception.NoValidPeerException;
import org.hyperledger.fabric.sdk.exception.RegistrationException;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;
import org.hyperledger.fabric.sdk.transaction.DeployRequest;
import org.hyperledger.fabric.sdk.transaction.DeploymentProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.ProposalBuilder;
import org.hyperledger.fabric.sdk.transaction.TransactionBuilder;
import org.hyperledger.fabric.sdk.transaction.TransactionRequest;

import com.google.protobuf.ByteString;

import io.netty.util.internal.StringUtil;

import org.hyperledger.fabric.protos.common.Common.Envelope;
import org.hyperledger.fabric.protos.orderer.Ab;
import org.hyperledger.fabric.protos.peer.Chaincode.ChaincodeID;
import org.hyperledger.fabric.protos.peer.FabricProposal.Proposal;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse.Endorsement;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse.ProposalResponse;

/**
 * The class representing a chain with which the client SDK interacts.
 */
public class Chain {
	private static final Log logger = LogFactory.getLog(Chain.class);

    private Enrollment  enrollment=  null; //TODO How do we get ernollemnt with private keys?

    // Name of the chain is only meaningful to the client
    private String name;

    // The peers on this chain to which the client can connect
    private List<Peer> peers = new ArrayList<Peer>();
    
 // The orderers on this chain to which the client can connect
    private List<Orderer> orderers = new ArrayList<Orderer>();

    // Security enabled flag
    private boolean securityEnabled = true;

    // A member cache associated with this chain
    // TODO: Make an LRU to limit size of member cache
    private Map<String, Member> members = new HashMap<>();

    // The number of tcerts to get in each batch
    private int tcertBatchSize = 200;

    // The registrar (if any) that registers & enrolls new members/users
    private Member registrar;

    // The member services used for this chain
    private MemberServices memberServices;

    // The key-val store used for this chain
    private KeyValStore keyValStore;

    // Is in dev mode or network mode
    private boolean devMode = false;

    // If in prefetch mode, we prefetch tcerts from member services to help performance
    private boolean preFetchMode = true;

    // Temporary variables to control how long to wait for deploy and invoke to complete before
    // emitting events.  This will be removed when the SDK is able to receive events from the
    private int deployWaitTime = 20;
    private int invokeWaitTime = 5;

    // The crypto primitives object
    CryptoPrimitives cryptoPrimitives;

    public Chain(String name) {
        this.name = name;
    }

    /**
     * Get the chain name
     * @returns The name of the chain
     */
    public String getName() {
        return this.name;
    }

    /**
     * Add a peer given an endpoint specification.
     * @param url URL of the peer
     * @param pem
     * @returns a new peer.
     */
    public Peer addPeer(String url, String pem) {
        Peer peer = new Peer(url, pem, this);
        this.peers.add(peer);
        return peer;
    }
        
    /**
     * Get the peers for this chain.
     */
    public List<Peer> getPeers() {
        return this.peers;
    }
    
    /**
     * Add an orderer given an endpoint specification.
     * @param url URL of the orderer
     * @param pem
     * @returns a new Orderer.
     */
    public Orderer addOrderer(String url, String pem) {
        Orderer orderer = new Orderer(url, pem, this);
        this.orderers.add(orderer);
        return orderer;
    }
    
    /**
     * Get the orderers for this chain.
     */
    public List<Orderer> getOrderers() {
        return this.orderers;
    }

    /**
     * Get the registrar associated with this chain
     * @return The member whose credentials are used to perform registration, or undefined if not set.
     */
    public Member getRegistrar() {
        return this.registrar;
    }

    /**
     * Set the registrar
     * @param registrar The member whose credentials are used to perform registration.
     */
    public void setRegistrar(Member registrar) {
        this.registrar = registrar;
    }

    /**
     * Set the member services URL
     * @param url Member services URL of the form: "grpc://host:port" or "grpcs://host:port"
     * @param pem
     * @throws CertificateException
     */
    public void setMemberServicesUrl(String url, String pem) throws CertificateException {
        this.setMemberServices(new MemberServicesImpl(url,pem));
    }

    /**
     * Get the member service associated this chain.
     * @returns MemberServices associated with the chain, or undefined if not set.
     */
    public MemberServices getMemberServices() {
        return this.memberServices;
    };

    /**
     * Set the member service
     * @param memberServices The MemberServices instance
     */
    public void setMemberServices(MemberServices memberServices) {
        this.memberServices = memberServices;
        if (memberServices instanceof MemberServicesImpl) {
           this.cryptoPrimitives = ((MemberServicesImpl) memberServices).getCrypto();
        }
    };

    /**
     * Determine if security is enabled.
     * @return true if security is enabled, false otherwise
     */
    public boolean isSecurityEnabled() {
        return this.memberServices != null;
    }

    /**
     * Determine if pre-fetch mode is enabled to prefetch tcerts.
     * @return true if  pre-fetch mode is enabled, false otherwise
     */
    public boolean isPreFetchMode() {
        return this.preFetchMode;
    }

    /**
     * Set prefetch mode to true or false.
     */
    public void setPreFetchMode(boolean preFetchMode) {
        this.preFetchMode = preFetchMode;
    }

    /**
     * Determine if dev mode is enabled.
     */
    public boolean isDevMode() {
        return this.devMode;
    }

    /**
     * Set dev mode to true or false.
     */
    public void setDevMode(boolean devMode) {
        this.devMode = devMode;
    }

    /**
     * Get the deploy wait time in seconds.
     */
    public int getDeployWaitTime() {
        return this.deployWaitTime;
    }

    /**
     * Set the deploy wait time in seconds.
     * @param waitTime Deploy wait time
     */
    public void setDeployWaitTime(int waitTime) {
        this.deployWaitTime = waitTime;
    }

    /**
     * Get the invoke wait time in seconds
     * @return invoke wait time
     */
    public int getInvokeWaitTime() {
        return this.invokeWaitTime;
    }

    /**
     * Set the invoke wait time in seconds.
     * @param waitTime Invoke wait time
     */
    public void setInvokeWaitTime(int waitTime) {
        this.invokeWaitTime = waitTime;
    }

    /**
     * Get the key val store implementation (if any) that is currently associated with this chain.
     * @returnsThe current KeyValStore associated with this chain, or undefined if not set.
     */
    public KeyValStore getKeyValStore() {
        return this.keyValStore;
    }

    /**
     * Set the key value store implementation.
     */
    public void setKeyValStore(KeyValStore keyValStore) {
        this.keyValStore = keyValStore;
    }

    /**
     * Get the tcert batch size.
     */
    public int getTCertBatchSize() {
        return this.tcertBatchSize;
    }

    /**
     * Set the tcert batch size.
     */
    public void setTCertBatchSize(int batchSize) {
        this.tcertBatchSize = batchSize;
    }

    /**
     * Get the member with a given name
     * @return member
     */
    public Member getMember(String name) {
        if (null == keyValStore) throw new RuntimeException("No key value store was found.  You must first call Chain.setKeyValStore");
        if (null == memberServices) throw new RuntimeException("No member services was found.  You must first call Chain.setMemberServices or Chain.setMemberServicesUrl");

        // Try to get the member state from the cache
        Member member = (Member) members.get(name);
        if (null != member) return member;

        // Create the member and try to restore it's state from the key value store (if found).
        member = new Member(name, this);
        member.restoreState();
        return member;

    }

    /**
     * Get a user.
     * A user is a specific type of member.
     * Another type of member is a peer.
     */
    Member getUser(String name) {
        return getMember(name);
    }


    /**
     * Register a user or other member type with the chain.
     * @param registrationRequest Registration information.
     * @throws RegistrationException if the registration fails
     */
    public Member register(RegistrationRequest registrationRequest) throws RegistrationException {
        Member member = getMember(registrationRequest.getEnrollmentID());
	    member.register(registrationRequest);
	    return member;
    }

    /**
     * Enroll a user or other identity which has already been registered.
     * @param name The name of the user or other member to enroll.
     * @param secret The enrollment secret of the user or other member to enroll.
     * @throws EnrollmentException
     */

    public Member enroll(String name, String secret) throws EnrollmentException {
        Member member = getMember(name);
        member.enroll(secret);
        members.put(name, member);

        return member;
    }

    /**
     * Register and enroll a user or other member type.
     * This assumes that a registrar with sufficient privileges has been set.
     * @param registrationRequest Registration information.
     * @throws RegistrationException
     * @throws EnrollmentException
     */
    public Member registerAndEnroll(RegistrationRequest registrationRequest) throws RegistrationException, EnrollmentException {
        Member member = getMember(registrationRequest.getEnrollmentID());
        member.registerAndEnroll(registrationRequest);
        return member;
    }
    
    /**
     * Send a deployment proposal
     * @param deploymentProposalRequest
     * @return
     * @throws Exception
     */
    public Proposal createDeploymentProposal(DeployRequest deploymentRequest) {

        assert deploymentRequest != null: "sendDeploymentProposal deploymentProposalRequest is null";
        
        List<ByteString> args = new ArrayList<ByteString>();
        if (deploymentRequest.getArgs() != null) {
        	deploymentRequest.getArgs().forEach(arg->{
        		args.add(ByteString.copyFrom(arg.getBytes()));
        	});
        }        

//      TransactionContext transactionContext = new TransactionContext(this, this.client.getUserContext());
//      deploymentProposalbuilder.context(transactionContext);        
        Proposal deploymentProposal = DeploymentProposalBuilder.newBuilder()
        		.chaincodeType(deploymentRequest.getChaincodeLanguage())
        		.args(args)
        		.chaincodeID(ChaincodeID.newBuilder()
        				.setName(deploymentRequest.getChaincodeName())
        				.setPath(deploymentRequest.getChaincodePath())        				
        				.build())
        		.build();
                
        return deploymentProposal;
    }
    
    /**
     * Create transaction proposal
     * @param request The details of transaction 
     * @return proposal
     */
    public Proposal createTransactionProposal(TransactionRequest request) {
    	assert request != null : "Cannot send null transactopn proposal";
    	assert StringUtil.isNullOrEmpty(request.getChaincodeName()): "Chaincode name is missing in proposal";
    	
    	List<ByteString> args = new ArrayList<ByteString>();
    	if (request.getArgs() != null) {
    		for (String arg: request.getArgs()) {
    			args.add(ByteString.copyFrom(arg == null?new byte[]{}:arg.getBytes()));
    		}
    	}
    	
    	ChaincodeID ccid = ChaincodeID.newBuilder()
    			.setName(request.getChaincodeName())
    			.setPath(request.getChaincodePath())
    			.build();
    	
    	Proposal fabricProposal = ProposalBuilder.newBuilder()
    			.args(args)
    			.chaincodeType(request.getChaincodeLanguage())
    			.chaincodeID(ccid).build(); 
    	
    	return fabricProposal;
    }

    /**
     * Send a transaction proposal to the chain of peers.
     * @param proposal The transaction proposal
     * 
     * @return List<ProposalResponse>
     */
    public List<ProposalResponse> sendProposal(Proposal proposal) {
        if (this.peers.isEmpty()) {
            throw new NoValidPeerException(String.format("chain %s has no peers", getName()));
        }
        
        List<ProposalResponse> responses = new ArrayList<ProposalResponse>();

        for(Peer peer : peers) {
        	try {
        		responses.add(peer.sendTransactionProposal(proposal));
        	} catch(Exception exp) {
        		logger.info(String.format("Failed sending transaction to peer:%s", exp.getMessage()));
        	}
        }

        if (responses.size() == 0) {
        	throw new RuntimeException("No peer available to respond");
        }
        
        return responses;
    }
    
    /**
     * Send a transaction to orderers
     * @param proposalResponses list of responses from endorsers for the proposal
     * 
     * @return List<TransactionResponse>
     * @throws InvalidArgumentException
     */
    public List<TransactionResponse> sendTransaction(Proposal proposal, List<ProposalResponse> proposalResponses) throws InvalidProtocolBufferException, CryptoException {
    	assert proposalResponses != null && proposalResponses.size() > 0: "Please use sendProposal first to get endorsements";

    	if (this.orderers.isEmpty()) {
            throw new NoValidOrdererException(String.format("chain %s has no orderers", getName()));
        }
    	
        List<Endorsement> endorsements = new ArrayList<Endorsement>();
        ByteString proposalResponsePayload = proposalResponses.get(0).getPayload();
        proposalResponses.forEach(response->{
        	endorsements.add(response.getEndorsement());
        });

        ChaincodeProposal.ChaincodeProposalPayload  payload = ChaincodeProposal.ChaincodeProposalPayload.parseFrom(proposalResponsePayload);


        TransactionBuilder transactionBuilder = TransactionBuilder.newBuilder();

        Common.Payload commonPayload = transactionBuilder
                .cryptoPrimitives(cryptoPrimitives) //this has to use same hashing in cryptoPrimitives
                .chaincodeProposal(proposal)
                .endorsements(endorsements)
                .proposalResponcePayload(payload).build();

        Envelope signedEnvelope = createTransactionEnvelop(commonPayload);

        List<TransactionResponse> ordererResponses = new ArrayList<TransactionResponse>();
        for (Orderer orderer : orderers) {//TODO need to make async.
            Ab.BroadcastResponse resp = orderer.sendTransaction(signedEnvelope);
            TransactionResponse tresp = new TransactionResponse(null, null, resp.getStatusValue(), resp.getStatus().name());
            ordererResponses.add(tresp);
        }
        return ordererResponses;
    }




    private Common.Envelope createTransactionEnvelop(Common.Payload transactionPayload) throws CryptoException {

        Common.Envelope.Builder ceb = Common.Envelope.newBuilder();
        ceb.setPayload(transactionPayload.toByteString());


        byte[] ecdsaSignature = cryptoPrimitives.ecdsaSign(enrollment.getPrivateKey(), transactionPayload.toByteArray());
        ceb.setSignature(ByteString.copyFrom(ecdsaSignature));

        logger.debug("Done creating transaction ready for orderer");

        return ceb.build();
    }

}
