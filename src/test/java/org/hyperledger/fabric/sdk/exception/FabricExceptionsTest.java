/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *  http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package org.hyperledger.fabric.sdk.exception;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class FabricExceptionsTest {

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testBaseException1() throws BaseException {

        thrown.expect(BaseException.class);
        thrown.expectMessage("test");

        throw new BaseException("test");

    }

    @Test
    public void testBaseException2() throws BaseException {

        thrown.expect(BaseException.class);
        thrown.expectMessage("test");

        throw new BaseException(new BaseException("test"));

    }

    @Test
    public void testBaseException3() throws BaseException {

        thrown.expect(BaseException.class);
        thrown.expectMessage("test");

        throw new BaseException(new BaseException("test"));

    }

    @Test
    public void testChaincodeEndorsementPolicyParseException1() throws ChaincodeEndorsementPolicyParseException {

        thrown.expect(ChaincodeEndorsementPolicyParseException.class);
        thrown.expectMessage("test");

        throw new ChaincodeEndorsementPolicyParseException("test");

    }

    @Test
    public void testChaincodeEndorsementPolicyParseException2() throws ChaincodeEndorsementPolicyParseException {

        thrown.expect(ChaincodeEndorsementPolicyParseException.class);
        thrown.expectMessage("test");

        throw new ChaincodeEndorsementPolicyParseException("test",
                new ChaincodeEndorsementPolicyParseException("test"));

    }

    @Test
    public void testChaincodeException() throws ChaincodeException {
        BaseException baseException = new BaseException("test");
        thrown.expect(ChaincodeException.class);
        thrown.expectMessage("test");

        throw new ChaincodeException("test", baseException);

    }

    @Test
    public void testCryptoException1() throws CryptoException {

        thrown.expect(CryptoException.class);
        thrown.expectMessage("test");

        throw new CryptoException("test");

    }

    @Test
    public void testCryptoException2() throws CryptoException {

        thrown.expect(CryptoException.class);
        thrown.expectMessage("test");

        throw new CryptoException("test", new CryptoException("test"));

    }

    @Test
    public void testEventHubException1() throws EventHubException {

        thrown.expect(EventHubException.class);
        thrown.expectMessage("test");

        throw new EventHubException("test");

    }

    @Test
    public void testEventHubException2() throws EventHubException {

        thrown.expect(EventHubException.class);
        thrown.expectMessage("test");

        throw new EventHubException(new CryptoException("test"));

    }

    @Test
    public void testEventHubException3() throws EventHubException {

        thrown.expect(EventHubException.class);
        thrown.expectMessage("test");

        throw new EventHubException("test", new CryptoException("test"));

    }

    @Test
    public void testExecuteException1() throws ExecuteException {

        thrown.expect(ExecuteException.class);
        thrown.expectMessage("test");

        throw new ExecuteException("test");

    }

    @Test
    public void testExecuteException2() throws ExecuteException {

        thrown.expect(ExecuteException.class);
        thrown.expectMessage("test");

        throw new ExecuteException("test", new ExecuteException("test"));

    }

    @Test
    public void testGetTCertBatchException() throws GetTCertBatchException {

        thrown.expect(GetTCertBatchException.class);
        thrown.expectMessage("test");

        throw new GetTCertBatchException("test", new ExecuteException("test"));

    }

    @Test
    public void testInvalidArgumentException1() throws InvalidArgumentException {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("test");

        throw new InvalidArgumentException("test");

    }

    @Test
    public void testInvalidArgumentException2() throws InvalidArgumentException {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("test");

        throw new InvalidArgumentException(new InvalidArgumentException("test"));

    }

    @Test
    public void testInvalidArgumentException3() throws InvalidArgumentException {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage("test");

        throw new InvalidArgumentException("test", new InvalidArgumentException("test"));

    }

    @Test
    public void testInvalidTransactionException1() throws InvalidTransactionException {

        thrown.expect(InvalidTransactionException.class);
        thrown.expectMessage("test");

        throw new InvalidTransactionException("test");

    }

    @Test
    public void testInvalidTransactionException2() throws InvalidTransactionException {

        thrown.expect(InvalidTransactionException.class);
        thrown.expectMessage("test");

        throw new InvalidTransactionException("test", new InvalidTransactionException("test"));

    }

    @Test
    public void testInvokeException() throws InvokeException {

        BaseException baseException = new BaseException("test");
        thrown.expect(InvokeException.class);
        thrown.expectMessage("test");

        throw new InvokeException("test", baseException);

    }

    @Test
    public void testNoAvailableTCertException() throws NoAvailableTCertException {

        thrown.expect(NoAvailableTCertException.class);
        thrown.expectMessage("test");

        throw new NoAvailableTCertException("test");

    }

    @Test
    public void testNoValidPeerException() throws NoValidPeerException {

        thrown.expect(NoValidPeerException.class);
        thrown.expectMessage("test");

        throw new NoValidPeerException("test");

    }

    @Test
    public void testPeerException1() throws PeerException {

        thrown.expect(PeerException.class);
        thrown.expectMessage("test");

        throw new PeerException("test");

    }

    @Test
    public void testPeerException2() throws PeerException {

        thrown.expect(PeerException.class);
        thrown.expectMessage("test");

        throw new PeerException("test", new PeerException("test"));

    }

    @Test
    public void testProposalException1() throws ProposalException {

        thrown.expect(ProposalException.class);
        thrown.expectMessage("test");

        throw new ProposalException("test");

    }

    @Test
    public void testProposalException2() throws ProposalException {

        thrown.expect(ProposalException.class);
        thrown.expectMessage("test");

        throw new ProposalException(new ProposalException("test"));

    }

    @Test
    public void testProposalException3() throws ProposalException {

        thrown.expect(ProposalException.class);
        thrown.expectMessage("test");

        throw new ProposalException("test", new ProposalException("test"));

    }

    @Test
    public void testQueryException() throws QueryException {
        BaseException baseException = new BaseException("test");
        thrown.expect(QueryException.class);
        thrown.expectMessage("test");

        throw new QueryException("test", baseException);

    }

    @Test
    public void testTransactionException1() throws TransactionException {
        thrown.expect(TransactionException.class);
        thrown.expectMessage("test");

        throw new TransactionException("test");

    }

    @Test
    public void testTransactionException2() throws TransactionException {
        thrown.expect(TransactionException.class);
        thrown.expectMessage("test");

        throw new TransactionException(new TransactionException("test"));

    }

    @Test
    public void testTransactionException3() throws TransactionException {
        thrown.expect(TransactionException.class);
        thrown.expectMessage("test");

        throw new TransactionException("test", new TransactionException("test"));

    }
}
