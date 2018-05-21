/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk.transaction;


import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.ProposalException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;


public class InstantiateProposalBuilderTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testBuild() throws Exception {

        thrown.expect(ProposalException.class);
        thrown.expectMessage("IO Error");

        InstantiateProposalBuilder builder = InstantiateProposalBuilder.newBuilder();
        builder.build();

    }

    @Test
    public void testInvalidType() throws Exception {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("Chaincode type is required");

        InstantiateProposalBuilder builder = InstantiateProposalBuilder.newBuilder();
        builder.chaincodeType(null);

        builder.build();
    }


}
