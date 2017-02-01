/*
 *  Copyright 2016 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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




public class InvokeProposalRequest extends TransactionRequest{
    private InvokeProposalRequest(){

    }
    public static InvokeProposalRequest newInstance() {
        return new InvokeProposalRequest();


    }

//    Chaincode.ChaincodeID chaincodeId;
//    String fcn;
//    String[] args;
//
//    public Chaincode.ChaincodeID getChaincodeId() {
//        return chaincodeId;
//    }
//
//    public String getFcn() {
//        return fcn;
//    }
//
//    public String[] getArgs() {
//        return args;
//    }
//
//    public void setChaincodeId(Chaincode.ChaincodeID chaincodeId) {
//        this.chaincodeId = chaincodeId;
//    }
//
//    public void setFcn(String fcn) {
//        this.fcn = fcn;
//    }
//
//    public void setArgs(String[] args) {
//        this.args = args;
//    }
//
//    public static InvokeProposalRequest newInstance(){
//        return new InvokeProposalRequest();
//    }
//



    /*
    var request = {
				target: hfc.getPeer('grpc://localhost:7051'),
				chaincodeId : chaincode_id,
				fcn: 'invoke',
				args: ['move', 'a', 'b','100']
			};
     */
}
