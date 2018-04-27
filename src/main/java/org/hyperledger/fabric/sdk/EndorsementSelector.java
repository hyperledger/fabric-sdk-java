/*
 *
 *  Copyright 2016,2018 DTCC, IBM - All Rights Reserved.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */

package org.hyperledger.fabric.sdk;

public interface EndorsementSelector {
    ServiceDiscovery.SDEndorserState endorserSelector(ServiceDiscovery.SDChaindcode sdChaindcode);

    EndorsementSelector ENDORSEMENT_SELECTION_RANDOM = ServiceDiscovery.ENDORSEMENT_SELECTION_RANDOM;
    EndorsementSelector ENDORSEMENT_SELECTION_LEAST_REQUIRED_BLOCKHEIGHT = ServiceDiscovery.ENDORSEMENT_SELECTION_LEAST_REQUIRED_BLOCKHEIGHT;
}
