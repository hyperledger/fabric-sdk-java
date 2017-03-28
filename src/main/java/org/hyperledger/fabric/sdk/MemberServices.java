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

import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.hyperledger.fabric.sdk.exception.GetTCertBatchException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric_ca.sdk.exception.RegistrationException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric_ca.sdk.RegistrationRequest;
import org.hyperledger.fabric_ca.sdk.exception.RevocationException;

public interface MemberServices {

    /**
     * @param cryptoSuite the {@link CryptoSuite} instance for use with signing and signature verification
     */
    public void setCryptoSuite(CryptoSuite cryptoSuite);

    /**
     * @return the {@link CryptoSuite} associated with this MemberServices instance.
     */
    public CryptoSuite getCryptoSuite();

    /**
     * Register the user and return an enrollment secret.
     * @param req Registration request with the following fields: name, role
     * @param registrar The identity of the registar (i.e. who is performing the registration)
     * @return enrollment secret
     */
    String register(RegistrationRequest req, User registrar) throws RegistrationException, InvalidArgumentException;

    /**
     * Enroll the user and return an opaque user object
     * @param userName Name of usr to enroll
     * @param secret enrollmentSecret
     *
     * @return enrollment details
     */
    Enrollment enroll(String userName, String secret) throws EnrollmentException, InvalidArgumentException;

    /**
     * Re-enroll the user and return a new Enrollment of the user
     * @param user usr to be re-enroll
     * @return enrollment details
     */
    Enrollment reenroll(User user) throws EnrollmentException, InvalidArgumentException;

    /**
     * Revoke one enrollment of user
     * @param revoker admin user who has revoker attribute configured in CA-server
     * @param enrollment the user enrollment to be revoked
     * @param reason revoke reason, see RFC 5280
     */
    void revoke(User revoker, Enrollment enrollment, int reason) throws RevocationException, InvalidArgumentException;

    /**
     * Revoke all enrollment of user
     * @param revoker amdin user who has revoker attribute configured in CA-server
     * @param revokeeName name of user who to be revoked
     * @param reason revoke reason, see RFC 5280
     */
    void revoke(User revoker, String revokeeName, int reason) throws RevocationException, InvalidArgumentException;
    /**
     * Get an array of transaction certificates (tcerts).
     * @param req A GetTCertBatchRequest
     */
    void getTCertBatch(GetTCertBatchRequest req) throws GetTCertBatchException;



}
