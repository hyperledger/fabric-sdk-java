/*
 *  Copyright 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *      http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

 package org.hyperledger.fabric_ca.sdk;

import java.io.StringReader;
import java.net.MalformedURLException;
import java.util.Properties;

import javax.json.Json;
import javax.json.JsonObject;
import javax.json.JsonReader;

import org.apache.http.auth.UsernamePasswordCredentials;
import org.hyperledger.fabric_ca.sdk.exception.EnrollmentException;
import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;

import static java.lang.String.format;

/**
 * A Mock class for testing HFCAClient.java
 *
 */

public class MockHFCAClient extends HFCAClient {

    private String httpPostResponse = null;

    MockHFCAClient(String name, String url, Properties properties) throws MalformedURLException {
        super(name, url, properties);
    }

    @Override
    String httpPost(String url, String body, UsernamePasswordCredentials credentials) throws Exception {
        return httpPostResponse == null ? super.httpPost(url, body, credentials) : httpPostResponse;
    }

    @Override
    JsonObject httpPost(String url, String body, String authHTTPCert) throws Exception {

        JsonObject response;

        if (httpPostResponse == null) {
            response = super.httpPost(url, body, authHTTPCert);
        } else {
            JsonReader reader = Json.createReader(new StringReader(httpPostResponse));
            response = (JsonObject) reader.read();

            // TODO: HFCAClient could do with some minor refactoring to avoid duplicating this code here!!
            JsonObject result = response.getJsonObject("result");
            if (result == null) {
                EnrollmentException e = new EnrollmentException(
                        format("POST request to %s failed request body %s " + "Body of response did not contain result",
                                url, body),
                        new Exception());
                throw e;
            }
        }
        return response;
    }

    public static MockHFCAClient createNewInstance(String url, Properties properties) throws MalformedURLException {

        return new MockHFCAClient(null, url, properties);
    }

    public static MockHFCAClient createNewInstance(String name, String url, Properties properties)
            throws MalformedURLException, InvalidArgumentException {

        if (name == null || name.isEmpty()) {

            throw new InvalidArgumentException("name must not be null or an empty string.");
        }

        return new MockHFCAClient(name, url, properties);
    }

    // Sets the test string to be returned from httpPost
    // If null, it returns the actual response
    public void setHttpPostResponse(String httpPostResponse) {
        this.httpPostResponse = httpPostResponse;
    }

}
