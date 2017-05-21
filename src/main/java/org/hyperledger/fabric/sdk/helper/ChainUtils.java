/*
Copyright DTCC 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

         http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package org.hyperledger.fabric.sdk.helper;

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequenceGenerator;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.security.CryptoSuite;


public class ChainUtils {

    public static CryptoSuite suite = null;
   /**
     * used asn1 and get hash
     * @param blockNumber
     * @param previousHash
     * @param dataHash
     * @return byte[]
     * @throws IOException
     * @throws InvalidArgumentException
     */
    public static byte[] calculateBlockHash(long blockNumber, byte[] previousHash, byte[] dataHash) throws IOException, InvalidArgumentException{

        if (previousHash == null) {
            throw new InvalidArgumentException("previousHash parameter is null.");
        }
        if (dataHash == null) {
            throw new InvalidArgumentException("dataHash parameter is null.");
        }

        if(null == suite){
            suite = CryptoSuite.Factory.getCryptoSuite();
        }

        ByteArrayOutputStream s = new ByteArrayOutputStream();
        DERSequenceGenerator seq = new DERSequenceGenerator(s);
        seq.addObject(new ASN1Integer(blockNumber));
        seq.addObject(new DEROctetString(previousHash));
        seq.addObject(new DEROctetString(dataHash));
        seq.close();
        return suite.hash(s.toByteArray());

    }
}
