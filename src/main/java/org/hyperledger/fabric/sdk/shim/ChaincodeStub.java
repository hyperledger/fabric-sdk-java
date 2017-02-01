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

package org.hyperledger.fabric.sdk.shim;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
//import org.hyperledger.protos.peer.Chaincode.ChaincodeSecurityContext;
//import org.hyperledger.protos.peer.TableProto;
import org.hyperledger.fabric.sdk.shim.crypto.signature.EcdsaSignatureVerifier;
import org.hyperledger.fabric.protos.peer.Chaincode;

import com.google.protobuf.ByteString;

//import static org.hyperledger.protos.TableProto.ColumnDefinition.Type.STRING;

public class ChaincodeStub {
    private static Log logger = LogFactory.getLog(ChaincodeStub.class);
    private final String uuid;
    private final Handler handler;
//    private final ChaincodeSecurityContext securityContext;

//    public ChaincodeStub(String uuid, Handler handler, ChaincodeSecurityContext securityContext) {
    public ChaincodeStub(String uuid, Handler handler) {
        this.uuid = uuid;
        this.handler = handler;
//        this.securityContext = securityContext;
    }

    /**
     * Gets the UUID of this stub
     *
     * @return the id used to identify this communication channel
     */
    public String getUuid() {
        return uuid;
    }

    /**
     * Get the state of the provided key from the ledger, and returns is as a string
     *
     * @param key the key of the desired state
     * @return the String value of the requested state
     */
    public String getState(String key) {
        return handler.handleGetState(key, uuid).toStringUtf8();
    }

    /**
     * Puts the given state into a ledger, automatically wrapping it in a ByteString
     *
     * @param key   reference key
     * @param value value to be put
     */
    public void putState(String key, String value) {
        handler.handlePutState(key, ByteString.copyFromUtf8(value), uuid);
    }

    /**
     * Deletes the state of the given key from the ledger
     *
     * @param key key of the state to be deleted
     */
    public void delState(String key) {
        handler.handleDeleteState(key, uuid);
    }

    /**
     * Given a start key and end key, this method returns a map of items with value converted to UTF-8 string.
     *
     * @param startKey
     * @param endKey
     * @return
     */
    public Map<String, String> rangeQueryState(String startKey, String endKey) {
        Map<String, String> retMap = new HashMap<>();
        for (Map.Entry<String, ByteString> item : rangeQueryRawState(startKey, endKey).entrySet()) {
            retMap.put(item.getKey(), item.getValue().toStringUtf8());
        }
        return retMap;
    }

    /**
     * This method is same as rangeQueryState, except it returns value in ByteString, useful in cases where
     * serialized object can be retrieved.
     *
     * @param startKey
     * @param endKey
     * @return
     */
    public Map<String, ByteString> rangeQueryRawState(String startKey, String endKey) {
        Map<String, ByteString> map = new HashMap<>();
        /*for (Chaincode.RangeQueryStateKeyValue mapping : handler.handleRangeQueryState(
                startKey, endKey, uuid).getKeysAndValuesList()) {
            map.put(mapping.getKey(), mapping.getValue());
        }*/ //TODO: Satheesh, uncomment above block
        return map;
    }

    /**
     * @param chaincodeName
     * @param function
     * @param args
     * @return
     */
    public String invokeChaincode(String chaincodeName, String function, List<ByteString> args) {
        return handler.handleInvokeChaincode(chaincodeName, function, args, uuid).toStringUtf8();
    }


    //------RAW CALLS------

    /**
     * @param key
     * @return
     */
    public ByteString getRawState(String key) {
        return handler.handleGetState(key, uuid);
    }

    /**
     * @param key
     * @param value
     */
    public void putRawState(String key, ByteString value) {
        handler.handlePutState(key, value, uuid);
    }

    /**
     * Invokes the provided chaincode with the given function and arguments, and returns the
     * raw ByteString value that invocation generated.
     *
     * @param chaincodeName The name of the chaincode to invoke
     * @param function      the function parameter to pass to the chaincode
     * @param args          the arguments to be provided in the chaincode call
     * @return the value returned by the chaincode call
     */
    public ByteString invokeRawChaincode(String chaincodeName, String function, List<ByteString> args) {
        return handler.handleInvokeChaincode(chaincodeName, function, args, uuid);
    }


    public boolean verifySignature(byte[] cert, byte[] signature, byte[] payload){
        return new EcdsaSignatureVerifier().verify(cert, signature, payload);
    }
}
