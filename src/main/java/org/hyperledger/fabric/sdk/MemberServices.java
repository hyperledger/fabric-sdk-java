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

import org.hyperledger.fabric.sdk.exception.EnrollmentException;
import org.hyperledger.fabric.sdk.exception.GetTCertBatchException;
import org.hyperledger.fabric.sdk.exception.RegistrationException;

import java.util.List;

public interface MemberServices {

    /**
     * Get the security level
     * @returns The security level
     */
    int getSecurityLevel();

    /**
     * Set the security level
     * @params securityLevel The security level
     */
    void setSecurityLevel(int securityLevel);

    /**
     * Get the hash algorithm
     * @returns The security level
     */
    String getHashAlgorithm();

    /**
     * Set the security level
     * @params securityLevel The security level
     */
    void setHashAlgorithm(String hashAlgorithm);

    /**
     * Register the user and return an enrollment secret.
     * @param req Registration request with the following fields: name, role
     * @param registrar The identity of the registar (i.e. who is performing the registration)
     * @return enrollment secret
     */
    String register(RegistrationRequest req, User registrar) throws RegistrationException;

    /**
     * Enroll the user and return an opaque user object
     * @param req Enrollment request with the following fields: name, enrollmentSecret
     *
     * @return enrollment details
     */
    Enrollment enroll(EnrollmentRequest req) throws EnrollmentException;

    /**
     * Get an array of transaction certificates (tcerts).
     * @param req A GetTCertBatchRequest
     */
    void getTCertBatch(GetTCertBatchRequest req) throws GetTCertBatchException;

}
