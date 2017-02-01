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

/**
 * A registration request is information required to register a user, peer, or other
 * type of member.
 */
public class RegistrationRequest {
    // The enrollment ID of the user
    private String enrollmentID;
    // Roles associated with this member.
    // Fabric roles include: 'client', 'peer', 'validator', 'auditor'
    // Default value: ['client']
    private ArrayList<String> roles;
    // Affiliation for a user
    private String affiliation;
    // 'registrar' enables this identity to register other members with types
    // and can delegate the 'delegationRoles' roles
	public String getEnrollmentID() {
		return enrollmentID;
	}
	public void setEnrollmentID(String enrollmentID) {
		this.enrollmentID = enrollmentID;
	}
	public ArrayList<String> getRoles() {
		return roles;
	}
	public void setRoles(ArrayList<String> roles) {
		this.roles = roles;
	}
	public String getAffiliation() {
		return affiliation;
	}
	public void setAffiliation(String affiliation) {
		this.affiliation = affiliation;
	}

    //TODO uncomment registrar
    /*
    registrar?:{
        // The allowable roles which this member can register
        roles:string[],
        // The allowable roles which can be registered by members registered by this member
        delegateRoles?:string[]
    };
    */
}
