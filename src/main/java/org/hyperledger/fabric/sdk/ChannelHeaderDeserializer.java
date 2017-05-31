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

import com.google.protobuf.ByteString;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.Timestamp;
import org.hyperledger.fabric.protos.common.Common.ChannelHeader;
import org.hyperledger.fabric.sdk.exception.InvalidProtocolBufferRuntimeException;

class ChannelHeaderDeserializer {
    private final ByteString byteString;
    private WeakReference<ChannelHeader> channelHeader;

    ChannelHeaderDeserializer(ByteString byteString) {
        this.byteString = byteString;
    }

    ChannelHeader getChannelHeader() {
        ChannelHeader ret = null;

        if (channelHeader != null) {
            ret = channelHeader.get();

        }
        if (null == ret) {
            try {
                ret = ChannelHeader.parseFrom(byteString);
            } catch (InvalidProtocolBufferException e) {
                throw new InvalidProtocolBufferRuntimeException(e);
            }
            channelHeader = new WeakReference<>(ret);

        }

        return ret;

    }

    String getChannelId() {
        return getChannelHeader().getChannelId();
    }

    long getEpoch() {
        return getChannelHeader().getEpoch();
    }

    Timestamp getTimestamp() {
        return getChannelHeader().getTimestamp();
    }

    String getTxId() {
        return getChannelHeader().getTxId();
    }

    int getType() {
        return getChannelHeader().getType();
    }

    int getVersion() {
        return getChannelHeader().getVersion();
    }
}
