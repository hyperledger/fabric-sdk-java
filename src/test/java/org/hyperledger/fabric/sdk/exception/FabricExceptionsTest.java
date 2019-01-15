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

import com.google.protobuf.InvalidProtocolBufferException;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class FabricExceptionsTest {

    private static final String MESSAGE = "test";

    @Rule
    public ExpectedException thrown = ExpectedException.none();

    @Test
    public void testBaseException1() throws BaseException {

        thrown.expect(BaseException.class);
        thrown.expectMessage(MESSAGE);

        throw new BaseException(MESSAGE);

    }

    @Test
    public void testBaseException2() throws BaseException {

        thrown.expect(BaseException.class);
        thrown.expectMessage(MESSAGE);

        throw new BaseException(new BaseException(MESSAGE));

    }

    @Test
    public void testBaseException3() throws BaseException {

        thrown.expect(BaseException.class);
        thrown.expectMessage(MESSAGE);

        throw new BaseException(new BaseException(MESSAGE));

    }

    @Test
    public void testChaincodeEndorsementPolicyParseException1() throws ChaincodeEndorsementPolicyParseException {

        thrown.expect(ChaincodeEndorsementPolicyParseException.class);
        thrown.expectMessage(MESSAGE);

        throw new ChaincodeEndorsementPolicyParseException(MESSAGE);

    }

    @Test
    public void testChaincodeEndorsementPolicyParseException2() throws ChaincodeEndorsementPolicyParseException {

        thrown.expect(ChaincodeEndorsementPolicyParseException.class);
        thrown.expectMessage(MESSAGE);

        throw new ChaincodeEndorsementPolicyParseException(MESSAGE,
                new ChaincodeEndorsementPolicyParseException(MESSAGE));

    }

    @Test
    public void testChaincodeException() throws ChaincodeException {
        BaseException baseException = new BaseException(MESSAGE);
        thrown.expect(ChaincodeException.class);
        thrown.expectMessage(MESSAGE);

        throw new ChaincodeException(MESSAGE, baseException);

    }

    @Test
    public void testCryptoException1() throws CryptoException {

        thrown.expect(CryptoException.class);
        thrown.expectMessage(MESSAGE);

        throw new CryptoException(MESSAGE);

    }

    @Test
    public void testCryptoException2() throws CryptoException {

        thrown.expect(CryptoException.class);
        thrown.expectMessage(MESSAGE);

        throw new CryptoException(MESSAGE, new CryptoException(MESSAGE));

    }

    @Test
    public void testEventHubException1() throws EventingException {

        thrown.expect(EventingException.class);
        thrown.expectMessage(MESSAGE);

        throw new EventingException(MESSAGE);

    }

    @Test
    public void testEventHubException2() throws EventingException {

        thrown.expect(EventingException.class);
        thrown.expectMessage(MESSAGE);

        throw new EventingException(new CryptoException(MESSAGE));

    }

    @Test
    public void testEventHubException3() throws EventingException {

        thrown.expect(EventingException.class);
        thrown.expectMessage(MESSAGE);

        throw new EventingException(MESSAGE, new CryptoException(MESSAGE));

    }

    @Test
    public void testExecuteException1() throws ExecuteException {

        thrown.expect(ExecuteException.class);
        thrown.expectMessage(MESSAGE);

        throw new ExecuteException(MESSAGE);

    }

    @Test
    public void testExecuteException2() throws ExecuteException {

        thrown.expect(ExecuteException.class);
        thrown.expectMessage(MESSAGE);

        throw new ExecuteException(MESSAGE, new ExecuteException(MESSAGE));

    }

    @Test
    public void testGetTCertBatchException() throws GetTCertBatchException {

        thrown.expect(GetTCertBatchException.class);
        thrown.expectMessage(MESSAGE);

        throw new GetTCertBatchException(MESSAGE, new ExecuteException(MESSAGE));

    }

    @Test
    public void testInvalidArgumentException1() throws InvalidArgumentException {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage(MESSAGE);

        throw new InvalidArgumentException(MESSAGE);

    }

    @Test
    public void testInvalidArgumentException2() throws InvalidArgumentException {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage(MESSAGE);

        throw new InvalidArgumentException(new InvalidArgumentException(MESSAGE));

    }

    @Test
    public void testInvalidArgumentException3() throws InvalidArgumentException {

        thrown.expect(InvalidArgumentException.class);
        thrown.expectMessage(MESSAGE);

        throw new InvalidArgumentException(MESSAGE, new InvalidArgumentException(MESSAGE));

    }

    @Test
    public void testInvalidTransactionException1() throws InvalidTransactionException {

        thrown.expect(InvalidTransactionException.class);
        thrown.expectMessage(MESSAGE);

        throw new InvalidTransactionException(MESSAGE);

    }

    @Test
    public void testInvalidTransactionException2() throws InvalidTransactionException {

        thrown.expect(InvalidTransactionException.class);
        thrown.expectMessage(MESSAGE);

        throw new InvalidTransactionException(MESSAGE, new InvalidTransactionException(MESSAGE));

    }

    @Test
    public void testInvokeException() throws InvokeException {

        BaseException baseException = new BaseException(MESSAGE);
        thrown.expect(InvokeException.class);
        thrown.expectMessage(MESSAGE);

        throw new InvokeException(MESSAGE, baseException);

    }

    @Test
    public void testNoAvailableTCertException() throws NoAvailableTCertException {

        thrown.expect(NoAvailableTCertException.class);
        thrown.expectMessage(MESSAGE);

        throw new NoAvailableTCertException(MESSAGE);

    }

    @Test
    public void testNoValidPeerException() throws NoValidPeerException {

        thrown.expect(NoValidPeerException.class);
        thrown.expectMessage(MESSAGE);

        throw new NoValidPeerException(MESSAGE);

    }

    @Test
    public void testPeerException1() throws PeerException {

        thrown.expect(PeerException.class);
        thrown.expectMessage(MESSAGE);

        throw new PeerException(MESSAGE);

    }

    @Test
    public void testPeerException2() throws PeerException {

        thrown.expect(PeerException.class);
        thrown.expectMessage(MESSAGE);

        throw new PeerException(MESSAGE, new PeerException(MESSAGE));

    }

    @Test
    public void testProposalException1() throws ProposalException {

        thrown.expect(ProposalException.class);
        thrown.expectMessage(MESSAGE);

        throw new ProposalException(MESSAGE);

    }

    @Test
    public void testProposalException2() throws ProposalException {

        thrown.expect(ProposalException.class);
        thrown.expectMessage(MESSAGE);

        throw new ProposalException(new ProposalException(MESSAGE));

    }

    @Test
    public void testProposalException3() throws ProposalException {

        thrown.expect(ProposalException.class);
        thrown.expectMessage(MESSAGE);

        throw new ProposalException(MESSAGE, new ProposalException(MESSAGE));

    }

    @Test
    public void testQueryException() throws QueryException {
        BaseException baseException = new BaseException(MESSAGE);
        thrown.expect(QueryException.class);
        thrown.expectMessage(MESSAGE);

        throw new QueryException(MESSAGE, baseException);

    }

    @Test
    public void testTransactionException1() throws TransactionException {
        thrown.expect(TransactionException.class);
        thrown.expectMessage(MESSAGE);

        throw new TransactionException(MESSAGE);

    }

    @Test
    public void testTransactionException2() throws TransactionException {
        thrown.expect(TransactionException.class);
        thrown.expectMessage(MESSAGE);

        throw new TransactionException(new TransactionException(MESSAGE));

    }

    @Test
    public void testTransactionException3() throws TransactionException {
        thrown.expect(TransactionException.class);
        thrown.expectMessage(MESSAGE);

        throw new TransactionException(MESSAGE, new TransactionException(MESSAGE));

    }

    @Test
    public void testTransactionEventException1() throws TransactionEventException {
        thrown.expect(TransactionException.class);
        thrown.expectMessage(MESSAGE);

        throw new TransactionEventException(MESSAGE, null);

    }

    @Test
    public void testTransactionEventException2() throws TransactionEventException {

        TransactionEventException e = new TransactionEventException(MESSAGE, null);
        Assert.assertNull(e.getTransactionEvent());

    }

    @Test
    public void testTransactionEventException3() throws TransactionEventException {
        thrown.expect(TransactionException.class);
        thrown.expectMessage(MESSAGE);

        throw new TransactionEventException(MESSAGE, null, new TransactionEventException(MESSAGE, null));

    }

    @Test
    public void testInvalidProtocolBufferRuntimeException1() throws InvalidProtocolBufferRuntimeException {
        thrown.expect(InvalidProtocolBufferRuntimeException.class);
        thrown.expectMessage(MESSAGE);

        throw new InvalidProtocolBufferRuntimeException(new InvalidProtocolBufferException(MESSAGE));

    }

    @Test
    public void testInvalidProtocolBufferRuntimeException2() throws InvalidProtocolBufferRuntimeException {
        thrown.expect(InvalidProtocolBufferRuntimeException.class);
        thrown.expectMessage(MESSAGE);

        throw new InvalidProtocolBufferRuntimeException(MESSAGE, new InvalidProtocolBufferException(MESSAGE));

    }

    @Test
    public void testInvalidProtocolBufferRuntimeException3() throws InvalidProtocolBufferRuntimeException {

        InvalidProtocolBufferException e1 = new InvalidProtocolBufferException(MESSAGE);
        InvalidProtocolBufferRuntimeException e2 = new InvalidProtocolBufferRuntimeException(MESSAGE, e1);

        Assert.assertEquals(e1, e2.getCause());

    }

}
