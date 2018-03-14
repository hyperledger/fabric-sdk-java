/*
 *
 *  Copyright 2016,2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import java.lang.ref.WeakReference;

import com.google.protobuf.InvalidProtocolBufferException;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.common.Common.Header;
import org.hyperledger.fabric.protos.msp.Identities;
import org.hyperledger.fabric.sdk.exception.InvalidProtocolBufferRuntimeException;

class HeaderDeserializer {

    private final Header header;
    private WeakReference<ChannelHeaderDeserializer> channelHeader;

    HeaderDeserializer(Header header) {
        this.header = header;
    }

    Header getHeader() {

        return header;
    }

    ChannelHeaderDeserializer getChannelHeader() {

        ChannelHeaderDeserializer ret = null;

        if (channelHeader != null) {
            ret = channelHeader.get();

        }
        if (ret == null) {

            ret = new ChannelHeaderDeserializer(getHeader().getChannelHeader());
            channelHeader = new WeakReference<>(ret);

        }

        return ret;

    }

    Identities.SerializedIdentity getCreator() {

        try {
            Common.SignatureHeader signatureHeader1 = Common.SignatureHeader.parseFrom(header.getSignatureHeader());
            return Identities.SerializedIdentity.parseFrom(signatureHeader1.getCreator());
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidProtocolBufferRuntimeException(e);
        }

    }

    byte[] getNonce() {

        try {
            Common.SignatureHeader signatureHeader1 = Common.SignatureHeader.parseFrom(header.getSignatureHeader());
            return signatureHeader1.getNonce().toByteArray();
        } catch (InvalidProtocolBufferException e) {
            throw new InvalidProtocolBufferRuntimeException(e);
        }

    }
}
