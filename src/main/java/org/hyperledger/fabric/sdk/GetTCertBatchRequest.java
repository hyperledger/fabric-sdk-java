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

package org.hyperledger.fabric.sdk;

import java.util.ArrayList;

// A request to get a batch of TCerts
public class GetTCertBatchRequest {

	private String name;
	private Enrollment enrollment;
	private int num;
	private ArrayList<String> attrs;

	public GetTCertBatchRequest( String name,
                Enrollment enrollment,
                int num,
                ArrayList<String> attrs) {
		this.name = name;
		this.enrollment = enrollment;
		this.num = num;
		this.attrs = attrs;
	}
}
