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

package org.hyperledger.fabric_ca.sdk.exception;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

public class FabricCAExceptionsTest {

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
    public void testEnrollmentException1() throws EnrollmentException {

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("test");

        throw new EnrollmentException("test");

    }

    @Test
    public void testEnrollmentException2() throws EnrollmentException {

        thrown.expect(EnrollmentException.class);
        thrown.expectMessage("test");

        throw new EnrollmentException("test", new EnrollmentException("test"));

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
    public void testRegistrationException() throws RegistrationException {

        BaseException baseException = new BaseException("test");
        thrown.expect(RegistrationException.class);
        thrown.expectMessage("test");

        throw new RegistrationException("test", baseException);

    }

    @Test
    public void testRevocationException() throws RevocationException {

        BaseException baseException = new BaseException("test");
        thrown.expect(RevocationException.class);
        thrown.expectMessage("test");

        throw new RevocationException("test", baseException);

    }
}
