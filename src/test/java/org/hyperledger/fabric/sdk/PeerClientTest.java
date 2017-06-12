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

package org.hyperledger.fabric.sdk;

//import java.security.cert.CertificateException;
//import java.util.ArrayList;
//import java.util.Arrays;
//import java.util.concurrent.TimeUnit;
//
//import org.hyperledger.fabric.sdk.exception.ChaincodeException;
//import org.hyperledger.fabric.sdk.exception.ProposalException;
//import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
//import org.hyperledger.fabric_ca.sdk.exception.RegistrationException;
//import org.junit.BeforeClass;
//import org.junit.Test;

public class PeerClientTest {

//  static Channel testChain = null;
//  static ChaincodeResponse deployResponse = null;
//  static ChaincodeResponse javaDeployResponse = null;
//
//  @BeforeClass
//  public static void setupChain() {
//      testChain = new Channel("chain1");
//      try {
//          testChain.setMemberServicesUrl("grpc://localhost:7054", null);
//          testChain.setKeyValStore(new SampleStore(System.getProperty("user.home")+"/test.properties"));
//          testChain.addPeer("grpc://localhost:7051", null);
//          //testChain.setDevMode(true);
//          SampleUser registrar = testChain.getUser("admin");
//          if (!registrar.isEnrolled()) {
//              registrar = testChain.enroll("admin", "Xurw3yU9zI0l");
//          }
//          testChain.setRegistrar(registrar);
//          deployResponse = deploy();
//          javaDeployResponse = deployJava();
//          TimeUnit.SECONDS.sleep(10);// deployment takes time, so wait for it to complete before making a query or invoke call
//      } catch(CertificateException | RegistrationException | EnrollmentException | InterruptedException cex) {
//          cex.printStackTrace();// TODO: Handle the exception properly
//      }
//  }
//
//
//  public static ChaincodeResponse deploy() throws RegistrationException, EnrollmentException, ProposalException {
//      InstallProposalRequest request = new InstallProposalRequest();
//      request.setChaincodePath("github.com/hyperledger/fabric/examples/chaincode/go/chaincode_example02");
//      request.setArgs(new ArrayList<>(Arrays.asList("init", "a", "700", "b", "20000")));
//      SampleUser user = getUser("User1", "bank_a");
//      request.setChaincodeName("mycc");
//      request.setChaincodeLanguage(ChaincodeLanguage.GO_LANG);
//      return user.deploy(request);
//  }
//
//  public static ChaincodeResponse deployJava() throws RegistrationException, EnrollmentException {
//      InstallProposalRequest request = new InstallProposalRequest();
//      request.setChaincodePath(System.getenv("GOPATH")+"/src/github.com/hyperledger/fabric/examples/chaincode/java/Example");
//      request.setArgs(new ArrayList<>(Arrays.asList("init", "a", "700", "b", "20000")));
//      SampleUser user = getUser("User1", "bank_a");
//      request.setChaincodeName("myccj");
//      request.setChaincodeLanguage(ChaincodeLanguage.JAVA);
//      return user.deploy(request);
//
//  }
//
//  @Test
//  public void testQuery() throws RegistrationException, EnrollmentException, ChaincodeException {
//      testInvoke(); // the amount is stored
//      QueryRequest request = new QueryRequest();
//      request.setArgs(new ArrayList<>(Arrays.asList("query", "a")));
//      request.setChaincodeID(deployResponse.getChaincodeID());
//      request.setChaincodeName(deployResponse.getChaincodeID());
//      SampleUser user = getUser("User1", "bank_a");
//      user.query(request);
//  }
//
//  @Test
//  public void testInvoke() throws RegistrationException, EnrollmentException, ChaincodeException {
//      InvokeRequest request = new InvokeRequest();
//      request.setArgs(new ArrayList<>(Arrays.asList("invoke", "a", "b", "200")));
//      request.setChaincodeID(deployResponse.getChaincodeID());
//      request.setChaincodeName(deployResponse.getChaincodeID());
//      SampleUser user = getUser("User1", "bank_a");
//      user.invoke(request);
//  }
//
//  @Test
//  public void testQueryJava() throws RegistrationException, EnrollmentException, ChaincodeException {
//      testInvokeJava();
//      QueryRequest request = new QueryRequest();
//      request.setArgs(new ArrayList<>(Arrays.asList("query", "a")));
//      request.setChaincodeID(javaDeployResponse.getChaincodeID());
//      request.setChaincodeName(javaDeployResponse.getChaincodeID());
//      request.setChaincodeLanguage(ChaincodeLanguage.JAVA);
//      SampleUser user = getUser("User1", "bank_a");
//      user.query(request);
//  }
//
//  @Test
//  public void testInvokeJava() throws RegistrationException, EnrollmentException, ChaincodeException {
//      InvokeRequest request = new InvokeRequest();
//      request.setArgs(new ArrayList<>(Arrays.asList("invoke", "a", "b", "200")));
//      request.setChaincodeID(javaDeployResponse.getChaincodeID());
//      request.setChaincodeName(javaDeployResponse.getChaincodeID());
//      request.setChaincodeLanguage(ChaincodeLanguage.JAVA);
//      SampleUser user = getUser("User1", "bank_a");
//      user.invoke(request);
//  }
//
//  private static SampleUser getUser(String enrollmentId, String affiliation) throws RegistrationException, EnrollmentException {
//      SampleUser user = testChain.getUser(enrollmentId);
//      if (!user.isRegistered()) {
//          RegistrationRequest registrationRequest = new RegistrationRequest();
//          registrationRequest.setEnrollmentID(enrollmentId);
//          registrationRequest.setAffiliation(affiliation);
//          //registrationRequest.setAccount(); TODO setAccount missing from registrationRequest?
//          user = testChain.registerAndEnroll(registrationRequest);
//      } else if (!user.isEnrolled()) {
//          user = testChain.enroll(enrollmentId, user.getEnrollmentSecret());
//      }
//      return user;
//  }
}
