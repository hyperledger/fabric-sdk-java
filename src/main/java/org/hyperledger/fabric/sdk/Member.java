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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.ArrayList;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.util.encoders.Hex;
import org.hyperledger.fabric.sdk.exception.EnrollmentException;
import org.hyperledger.fabric.sdk.exception.NoValidPeerException;
import org.hyperledger.fabric.sdk.exception.RegistrationException;

import io.netty.util.internal.StringUtil;

public class Member implements Serializable {
	private static final long serialVersionUID = 8077132186383604355L;

	private static final Log logger = LogFactory.getLog(Member.class);

    private transient Chain chain;
    private String name;
    private ArrayList<String> roles;
    private String account;
    private String affiliation;
    private String enrollmentSecret;
    private Enrollment enrollment = null;
    private transient MemberServices memberServices;
    private transient KeyValStore keyValStore;
    private String keyValStoreName;
//    private Map<String, TCertGetter> tcertGetterMap;
    private int tcertBatchSize;

    /**
     * Constructor for a member.
     * @param name The member name
     * @returns {Member} A member who is neither registered nor enrolled.
     */

    public Member(String name, Chain chain) {
    	if (chain == null) {
    		throw new IllegalArgumentException("A valid chain must be provided");
    	}

    	this.name = name;
    	this.chain = chain;
        this.memberServices = chain.getMemberServices();
        this.keyValStore = chain.getKeyValStore();
        this.keyValStoreName = toKeyValStoreName(this.name);
        this.tcertBatchSize = chain.getTCertBatchSize();
    }

    /**
     * Get the member name.
     * @returns {string} The member name.
     */
    public String getName() {
        return this.name;
    }

    /**
     * Get the chain.
     * @returns {Chain} The chain.
     */
    public Chain getChain() {
        return this.chain;
    }

    /**
     * Get the member services.
     * @returns {MemberServices} The member services.
     */

    public MemberServices getMemberServices() {
       return this.memberServices;
    }

    /**
     * Get the roles.
     * @returns {string[]} The roles.
     */
    public ArrayList<String> getRoles() {
        return this.roles;
    }

    /**
     * Set the roles.
     * @param roles {string[]} The roles.
     */
    public void setRoles(ArrayList<String> roles) {
        this.roles = roles;
    }

    /**
     * Get the account.
     * @returns {string} The account.
     */
    public String getAccount() {
        return this.account;
    }

    /**
     * Set the account.
     * @param account The account.
     */
    public void setAccount(String account) {
        this.account = account;
    }

    /**
     * Get the affiliation.
     * @returns {string} The affiliation.
     */
    public String getAffiliation() {
        return this.affiliation;
    }

    /**
     * Set the affiliation.
     * @param affiliation The affiliation.
     */
    public void setAffiliation(String affiliation) {
        this.affiliation = affiliation;
    }

    /**
     * Get the transaction certificate (tcert) batch size, which is the number of tcerts retrieved
     * from member services each time (i.e. in a single batch).
     * @returns The tcert batch size.
     */
    public int getTCertBatchSize() {
        if (this.tcertBatchSize <= 0) {
            return this.chain.getTCertBatchSize();
        } else {
            return this.tcertBatchSize;
        }
    }

    /**
     * Set the transaction certificate (tcert) batch size.
     * @param batchSize
     */
    public void setTCertBatchSize(int batchSize) {
        this.tcertBatchSize = batchSize;
    }

    /**
     * Get the enrollment logger.info.
     * @returns {Enrollment} The enrollment.
     */
    public Enrollment getEnrollment() {
        return this.enrollment;
    };

    /**
     * Determine if this name has been registered.
     * @returns {boolean} True if registered; otherwise, false.
     */
    public boolean isRegistered() {
        return this.isEnrolled() || !StringUtil.isNullOrEmpty(enrollmentSecret);
    }

    /**
     * Determine if this name has been enrolled.
     * @returns {boolean} True if enrolled; otherwise, false.
     */
    public boolean isEnrolled() {
        return this.enrollment != null;
    }

    /**
     * Register the member.
     * @param registrationRequest the registration request
     * @throws RegistrationException
     */
    public void register(RegistrationRequest registrationRequest) throws RegistrationException {
        if (!registrationRequest.enrollmentID.equals(getName())) {
            throw new RuntimeException("registration enrollment ID and member name are not equal");
        }

        this.enrollmentSecret = memberServices.register(registrationRequest, chain.getRegistrar());
        this.saveState();
    }

    /**
     * Enroll the member and return the enrollment results.
     * @param enrollmentSecret The password or enrollment secret as returned by register.
     * @return enrollment details
     * @throws EnrollmentException
     */
    public Enrollment enroll(String enrollmentSecret) throws EnrollmentException {
        EnrollmentRequest req = new EnrollmentRequest();
        req.setEnrollmentID(getName());
        req.setEnrollmentSecret(enrollmentSecret);
        logger.debug(String.format("Enrolling [req=%s]", req));

        this.enrollment = memberServices.enroll(req);
        this.saveState();
        return this.enrollment;
    }

    /**
     * Perform both registration and enrollment.
     * @throws RegistrationException
     * @throws EnrollmentException
     */
    public void registerAndEnroll(RegistrationRequest registrationRequest) throws RegistrationException, EnrollmentException {
        register(registrationRequest);
        enroll(this.enrollmentSecret);
    }

    /**
     * Issue a deploy request on behalf of this member.
     * @param deployRequest the request
     */
    public void deploy(DeployRequest deployRequest) {
        logger.debug("Member.deploy");

        if (getChain().getPeers().isEmpty()) {
        	throw new NoValidPeerException(String.format("chain %s has no peers", getChain().getName()));
        }

        getChain().getPeers().get(0).deploy(deployRequest);
    }

    /**
     * Issue a invoke request on behalf of this member.
     * @param invokeRequest the request
     */
    public void invoke(InvokeRequest invokeRequest) {
        logger.debug("Member.invoke");

        if (getChain().getPeers().isEmpty()) {
        	throw new NoValidPeerException(String.format("chain %s has no peers", getChain().getName()));
        }

        getChain().getPeers().get(0).invoke(invokeRequest);
    }

    /**
     * Issue a query request on behalf of this member.
     * @param queryRequest the request
     */
    public void query(QueryRequest queryRequest) {
        logger.debug("Member.query");

        if (getChain().getPeers().isEmpty()) {
        	throw new NoValidPeerException(String.format("chain %s has no peers", getChain().getName()));
        }

        getChain().getPeers().get(0).query(queryRequest);
    }

    /**
     * Create a transaction context with which to issue build, deploy, invoke, or query transactions.
     * Only call this if you want to use the same tcert for multiple transactions.
     * @param tcert A transaction certificate from member services.  This is optional.
     * @returns A transaction context.
     */
    public TransactionContext newTransactionContext(TCert tcert) {
        return new TransactionContext(this, tcert);
    }

    /**
     * Get a user certificate.
     * @param attrs The names of attributes to include in the user certificate.
     */
    public void getUserCert(String[] attrs) {
        this.getNextTCert(attrs);
    }

    /**
   * Get the next available transaction certificate with the appropriate attributes.
   */
   public void getNextTCert(String[] attrs) {

	   /*TODO implement getNextTCert
	   if (!self.isEnrolled()) {
            return cb(Error(util.format("user '%s' is not enrolled",self.getName())));
        }
        let key = getAttrsKey(attrs);
        logger.debug("Member.getNextTCert: key=%s",key);
        let tcertGetter = self.tcertGetterMap[key];
        if (!tcertGetter) {
            logger.debug("Member.getNextTCert: key=%s, creating new getter",key);
            tcertGetter = new TCertGetter(self,attrs,key);
            self.tcertGetterMap[key] = tcertGetter;
        }
        return tcertGetter.getNextTCert(cb);
        */
   }

   /**
    * Save the state of this member to the key value store.
    */
   public void saveState() {
	  ByteArrayOutputStream bos = new ByteArrayOutputStream();
	  try {
		ObjectOutputStream oos = new ObjectOutputStream(bos);
		oos.writeObject(this);
		oos.flush();
		keyValStore.setValue(keyValStoreName, Hex.toHexString(bos.toByteArray()));
		bos.close();
	} catch (IOException e) {
		logger.debug(String.format("Could not save state of member %s", this.name), e);
	}
   }

   /**
    * Restore the state of this member from the key value store (if found).  If not found, do nothing.
    */
   public void restoreState() {
		String memberStr = keyValStore.getValue(keyValStoreName);
		if (null != memberStr) {
			// The member was found in the key value store, so restore the
			// state.
			byte[] serialized = Hex.decode(memberStr);
			ByteArrayInputStream bis = new ByteArrayInputStream(serialized);
			try {
				ObjectInputStream ois = new ObjectInputStream(bis);
				Member state = (Member)ois.readObject();
				if (state != null) {
					this.name = state.name;
			        this.roles = state.roles;
			        this.account = state.account;
			        this.affiliation = state.affiliation;
			        this.enrollmentSecret = state.enrollmentSecret;
			        this.enrollment = state.enrollment;
				} else {
					logger.debug(String.format("Could not find member %s from keyvalue store", this.name));
				}
			} catch (IOException | ClassNotFoundException e) {
				logger.debug(String.format("Could not restore state of member %s", this.name), e);
			}
		}
   }

    public String getEnrollmentSecret() {
		return enrollmentSecret;
	}

	public void setEnrollmentSecret(String enrollmentSecret) {
		this.enrollmentSecret = enrollmentSecret;
	}

	public void setEnrollment(Enrollment enrollment) {
		this.enrollment = enrollment;
	}

    String toKeyValStoreName(String name) {
        return "member." + name;
    }    
}
