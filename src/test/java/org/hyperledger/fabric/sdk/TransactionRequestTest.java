/*
 *  Copyright 2020 IBM - All Rights Reserved.
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

import java.util.Optional;

import org.hyperledger.fabric.sdk.testutils.TestUtils;
import org.hyperledger.fabric.sdk.transaction.TransactionContext;
import org.junit.Assert;
import org.junit.Test;
import org.mockito.Mockito;

public class TransactionRequestTest {
    @Test(expected = NullPointerException.class)
    public void newWithNullUserThrows() {
        TransactionRequest request = new TransactionRequest(null);
    }

    @Test(expected = NullPointerException.class)
    public void testSetUserContextWithNullUserThrows() {
        User user = TestUtils.getMockUser("user", "mspId");
        TransactionRequest request = new TransactionRequest(user);

        request.setUserContext(null);
    }

    @Test
    public void testSetTransactionContext() {
        User user = TestUtils.getMockUser("user", "mspId");
        TransactionRequest request = new TransactionRequest(user);

        TransactionContext context = Mockito.mock(TransactionContext.class);
        Mockito.when(context.getUser()).thenReturn(user);

        request.setTransactionContext(context);

        Optional<TransactionContext> actual = request.getTransactionContext();
        Assert.assertTrue("Transaction context is present", actual.isPresent());
        Assert.assertEquals("Excepted context", context, actual.get());
    }

    @Test
    public void testSetTransactionContextAlsoSetsUserContext() {
        User oldUser = TestUtils.getMockUser("oldUser", "mspId");
        TransactionRequest request = new TransactionRequest(oldUser);

        TransactionContext context = Mockito.mock(TransactionContext.class);
        User newUser = TestUtils.getMockUser("newUser", "mspId");
        Mockito.when(context.getUser()).thenReturn(newUser);

        request.setTransactionContext(context);

        Assert.assertEquals(newUser, request.getUserContext());
    }

    @Test
    public void testSetUserContextRemovesTransactionContext() {
        User user = TestUtils.getMockUser("user", "mspId");
        TransactionRequest request = new TransactionRequest(user);

        TransactionContext context = Mockito.mock(TransactionContext.class);
        Mockito.when(context.getUser()).thenReturn(user);
        request.setTransactionContext(context);

        request.setUserContext(user);

        Assert.assertFalse(request.getTransactionContext().isPresent());
    }
}
