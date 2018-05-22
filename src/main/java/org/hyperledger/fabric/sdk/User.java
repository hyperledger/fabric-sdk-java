/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *   http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk;

import java.util.Set;

import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.helper.Utils;

import static java.lang.String.format;

/**
 * User - Is the interface needed to be implemented by embedding application of the SDK
 */
public interface User {

    /**
     * Get the name that identifies the user.
     *
     * @return the user name.
     */

    String getName();

    /**
     * Get the roles to which the user belongs.
     *
     * @return role names.
     */
    Set<String> getRoles();

    /**
     * Get the user's account
     *
     * @return the account name
     */
    String getAccount();

    /**
     * Get the user's affiliation.
     *
     * @return the affiliation.
     */
    String getAffiliation();

    /**
     * Get the user's enrollment certificate information.
     *
     * @return the enrollment information.
     */
    Enrollment getEnrollment();

    /**
     * Get the Membership Service Provider Identifier provided by the user's organization.
     *
     * @return MSP Id.
     */
    String getMspId();

    static void userContextCheck(User userContext) throws InvalidArgumentException {

        if (userContext == null) {
            throw new InvalidArgumentException("UserContext is null");
        }
        final String userName = userContext.getName();
        if (Utils.isNullOrEmpty(userName)) {
            throw new InvalidArgumentException("UserContext user's name missing.");
        }

        Enrollment enrollment = userContext.getEnrollment();
        if (enrollment == null) {
            throw new InvalidArgumentException(format("UserContext for user %s has no enrollment set.", userName));
        }

        if (Utils.isNullOrEmpty(userContext.getMspId())) {
            throw new InvalidArgumentException(format("UserContext for user %s  has user's MSPID missing.", userName));
        }

        if (Utils.isNullOrEmpty(enrollment.getCert())) {
            throw new InvalidArgumentException(format("UserContext for user %s enrollment missing user certificate.", userName));
        }
        if (null == enrollment.getKey()) {
            throw new InvalidArgumentException(format("UserContext for user %s has Enrollment missing signing key", userName));
        }

    }

}
