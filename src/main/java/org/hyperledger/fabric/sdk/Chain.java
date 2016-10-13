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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.sdk.exception.EnrollmentException;
import org.hyperledger.fabric.sdk.exception.NoValidPeerException;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;
import org.hyperledger.fabric.sdk.exception.RegistrationException;

import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;

/**
 * The class representing a chain with which the client SDK interacts.
 */
public class Chain {
	private static final Log logger = LogFactory.getLog(Chain.class);

    // Name of the chain is only meaningful to the client
    private String name;

    // The peers on this chain to which the client can connect
    private Vector<Peer> peers = new Vector<>();

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
    public Vector<Peer> getPeers() {
        return this.peers;
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
        Member member = getMember(registrationRequest.enrollmentID);
	    member.register(registrationRequest);
	    return member;
    }

    /**
     * Enroll a user or other identity which has already been registered.
     * @param name The name of the user or other member to enroll.
     * @param secret The enrollment secret of the user or other member to enroll.
     * @throws EnrollmentException
     */

    Member enroll(String name, String secret) throws EnrollmentException {
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
    Member registerAndEnroll(RegistrationRequest registrationRequest) throws RegistrationException, EnrollmentException {
        Member member = getMember(registrationRequest.enrollmentID);
        member.registerAndEnroll(registrationRequest);
        return member;
    }

    /**
     * Send a transaction to a peer.
     * @param tx The transaction
     */
    void sendTransaction(Transaction tx) {
        if (this.peers.isEmpty()) {
            throw new NoValidPeerException(String.format("chain %s has no peers", getName()));
        }

        for(Peer peer : peers) {
        	peer.sendTransaction(tx);
        }
        /*TODO implement sendTransaction
        let trySendTransaction = (pidx) => {
	       if( pidx >= peers.length ) {
		      eventEmitter.emit('error', new EventTransactionError("None of "+peers.length+" peers reponding"));
		      return;
	       }
	       let p = urlParser.parse(peers[pidx].getUrl());
	       let client = new net.Socket();
	       let tryNext = () => {
		      debug("Skipping unresponsive peer "+peers[pidx].getUrl());
		      client.destroy();
		      trySendTransaction(pidx+1);
	       }
	       client.on('timeout', tryNext);
	       client.on('error', tryNext);
	       client.connect(p.port, p.hostname, () => {
		   if( pidx > 0  &&  peers === this.peers )
		      this.peers = peers.slice(pidx).concat(peers.slice(0,pidx));
		   client.destroy();
		   peers[pidx].sendTransaction(tx, eventEmitter);
	    });
		}
		trySendTransaction(0);
    	}
    */
    }

}
