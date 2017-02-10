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
package org.hyperledger.fabric.sdk.shim;


import com.google.protobuf.ByteString;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse.Response;


public class ChaincodeResponseHelper {

    private static final int ERROR = Common.Status.INTERNAL_SERVER_ERROR_VALUE;
    private static final int SUCCESS = Common.Status.SUCCESS_VALUE;

    public static Response success(ByteString payLoad) {
        Response shimResponse = Response.newBuilder()
                .setStatus(SUCCESS)
                .setPayload(payLoad)
                .build();
        return shimResponse;
    }

    public static Response success(String payLoad) {
        Response shimResponse = Response.newBuilder()
                .setStatus(SUCCESS)
                .setPayload(ByteString.copyFromUtf8(payLoad))
                .build();
        return shimResponse;
    }

    public static Response error(ByteString payLoad) {
        Response shimResponse = Response.newBuilder()
                .setStatus(ERROR)
                .setPayload(payLoad)
                .build();
        return shimResponse;
    }

    public static Response error(String payLoad) {
        Response shimResponse = Response.newBuilder()
                .setStatus(ERROR)
                .setPayload(ByteString.copyFromUtf8(payLoad))
                .build();
        return shimResponse;
    }
    // To contain other ACL related error messages builders
    // with different status codes
    //private static final int FORBIDDEN = Common.Status.FORBIDDEN_VALUE;
}