/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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


import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.sdk.events.EventHub;
import org.hyperledger.fabric.sdk.exception.EnrollmentException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.RegistrationException;
import org.hyperledger.fabric.sdk.exception.TransactionException;
import org.hyperledger.fabric.sdk.security.CryptoPrimitives;

public class HFClient {

    private static final int DEFAULT_SECURITY_LEVEL = 256;  //TODO make configurable //Right now by default FAB services is using
    private static final String DEFAULT_HASH_ALGORITHM = "SHA2";  //Right now by default FAB services is using SHA2
    private final CryptoPrimitives cryptoPrimitives = new CryptoPrimitives(DEFAULT_HASH_ALGORITHM, DEFAULT_SECURITY_LEVEL);

    static {

        if (null == System.getProperty("org.hyperledger.fabric.sdk.logGRPC")) {
            // Turn this off by default!
            Logger.getLogger("io.netty").setLevel(Level.OFF);
            Logger.getLogger("io.grpc").setLevel(Level.OFF);

        }
    }

    private static final Log logger = LogFactory.getLog(HFClient.class);

    private final Map<String, Chain> chains = new HashMap<>();

    public User getUserContext() {
        return userContext;
    }

    private User userContext;

    // The key-val store used for this chain
    private KeyValStore keyValStore;

    // The member services used for this chain
    private MemberServices memberServices;

    private HFClient() {

    }

    CryptoPrimitives getCryptoPrimitives() {
        return cryptoPrimitives;
    }

//    public void setCryptoPrimitives(CryptoPrimitives cryptoPrimitives) {
//        this.cryptoPrimitives = cryptoPrimitives;
//    }


    /**
     * Get the key val store implementation (if any) that is currently associated with this chain.
     *
     * @return The current KeyValStore associated with this chain, or undefined if not set.
     */
    public KeyValStore getKeyValStore() {
        return this.keyValStore;
    }


    /**
     * Set the key value store implementation.
     *
     * @param keyValStore keystore value implementation
     */
    public void setKeyValStore(KeyValStore keyValStore) {
        this.keyValStore = keyValStore;
    }

    /**
     * createNewInstance create a new instance of the HFClient
     *
     * @return client
     */
    public static HFClient createNewInstance() {
        return new HFClient();
    }

    /**
     * newChain - already configured chain.
     * @param name
     * @return
     * @throws InvalidArgumentException
     */

    public Chain newChain(String name) throws InvalidArgumentException {
        logger.trace("Creating chain :" + name);
        Chain newChain = Chain.createNewInstance(name, this);
        chains.put(name, newChain);
        return newChain;
    }

    /**
     * Create a new chain
     * @param name The chains name
     * @param orderer  Order to create the chain with.
     * @param chainConfiguration Chain configration data.
     * @return
     * @throws TransactionException
     * @throws InvalidArgumentException
     */

    public Chain newChain(String name, Orderer orderer, ChainConfiguration chainConfiguration) throws TransactionException, InvalidArgumentException {

        logger.trace("Creating chain :" + name);
        Chain newChain = Chain.createNewInstance(name, this, orderer, chainConfiguration);
        chains.put(name, newChain);
        return newChain;
    }

    /**
     * newPeer create a new peer
     * @param grpcURL to the peer's location
     * @return Peer
     * @throws InvalidArgumentException
     */

    public Peer newPeer(String grpcURL) throws InvalidArgumentException {
        return Peer.createNewInstance(grpcURL, null);
    }

    /**
     * newPeer create a new peer
     * @param grpcURL to the peer's location
     * @param pem file used for TLS configuration
     * @return Peer
     * @throws InvalidArgumentException
     */

    public Peer newPeer(String grpcURL, String pem) throws InvalidArgumentException {
        return Peer.createNewInstance(grpcURL, pem);
    }


    /**
     * newOrderer Create a new Order
     *
     * @param grpcURL to the orderer's location
     * @return Orderer
     * @throws InvalidArgumentException
     */


    public Orderer newOrderer(String grpcURL) throws InvalidArgumentException {
        return Orderer.createNewInstance(grpcURL, null);
    }

    /**
     * Get the member service associated this chain.
     *
     * @return MemberServices associated with the chain, or undefined if not set.
     */
    public MemberServices getMemberServices() {
        return this.memberServices;
    }

    /**
     * Set the member service
     *
     * @param memberServices The MemberServices instance
     */
    public void setMemberServices(MemberServices memberServices) {
        this.memberServices = memberServices;
    }


    /**
     * getChain by name
     * @param name
     * @return
     */

    public Chain getChain(String name) {
        return chains.get(name);
    }

    /**
     * newInstallProposalRequest get new Install proposal request.
     * @return InstallProposalRequest
     */
    public InstallProposalRequest newInstallProposalRequest() {
        return new InstallProposalRequest();
    }

    /**
     * newInstantiationProposalRequest get new instantiation proposal request.
     * @return InstantiateProposalRequest
     */

    public InstantiateProposalRequest newInstantiationProposalRequest() {
        return new InstantiateProposalRequest();
    }

    /**
     * newInvokeProposalRequest  get new invoke proposal request.
     * @return InvokeProposalRequest
     */

    public InvokeProposalRequest newInvokeProposalRequest() {
        return InvokeProposalRequest.newInstance();
    }

    /**
     * newQueryProposalRequest get new query proposal request.
     * @return QueryProposalRequest
     */

    public QueryProposalRequest newQueryProposalRequest() {
        return QueryProposalRequest.newInstance();
    }

    /**
     * Set the User context for this client.
     *
     * @param userContext
     */

    public void setUserContext(User userContext) {
        this.userContext = userContext;
    }

    /**
     * newEventHub create a new event hub with pem
     *
     * @param url The http url location of the event hub
     * @param pem Pem file for TLS.
     * @return event hub
     */

    public EventHub newEventHub(String url, String pem) {
        return EventHub.createNewInstance(url, pem);
    }


    /**
     * newEventHub create a new event hub
     *
     * @param url The http url location of the event hub
     * @return event hub
     */

    public EventHub newEventHub(String url) {
        return EventHub.createNewInstance(url, null);
    }


    private final Map<String, User> members = new HashMap<>();

    /**
     * Register a user or other user type with the chain.
     *
     * @param registrationRequest Registration information.
     * @throws RegistrationException if the registration fails
     */
    public User register(RegistrationRequest registrationRequest) throws RegistrationException {
        User user = getMember(registrationRequest.getEnrollmentID());
        user.register(registrationRequest);
        return user;
    }

    /**
     * Enroll a user or other identity which has already been registered.
     *
     * @param name   The name of the user or other member to enroll.
     * @param secret The enrollment secret of the user or other member to enroll.
     * @throws EnrollmentException
     */

    public User enroll(String name, String secret) throws EnrollmentException {
        User user = getMember(name);
        if (!user.isEnrolled()) {
            user.enroll(secret);
        }

        members.put(name, user);

        return user;
    }

    /**
     * Register and enroll a user or other member type.
     * This assumes that a registrar with sufficient privileges has been set.
     *
     * @param registrationRequest Registration information.
     * @throws RegistrationException
     * @throws EnrollmentException
     */
    public User registerAndEnroll(RegistrationRequest registrationRequest) throws RegistrationException, EnrollmentException {
        User user = getMember(registrationRequest.getEnrollmentID());
        user.registerAndEnroll(registrationRequest);
        return user;
    }

    /**
     * Get the user with a given name
     *
     * @return user
     */
    public User getMember(String name) {
        if (null == keyValStore)
            throw new RuntimeException("No key value store was found.  You must first call Chain.setKeyValStore");
        if (null == memberServices)
            throw new RuntimeException("No user services was found.  You must first call Chain.setMemberServices or Chain.setMemberServicesUrl");

        // Try to get the user state from the cache
        User user = members.get(name);
        if (null != user) return user;

        // Create the user and try to restore it's state from the key value store (if found).
        user = new User(name, this);
        user.restoreState();
        return user;

    }


}
