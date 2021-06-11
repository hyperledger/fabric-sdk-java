/*
 *  Copyright 2016, 2017 DTCC, Fujitsu Australia Software Technology, IBM - All Rights Reserved.
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

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.util.Properties;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.common.Common;
import org.hyperledger.fabric.protos.orderer.Ab;
import org.hyperledger.fabric.protos.orderer.Ab.DeliverResponse;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.TransactionException;
import org.hyperledger.fabric.sdk.helper.Config;

import static java.lang.String.format;
import static org.hyperledger.fabric.sdk.helper.Utils.checkGrpcUrl;
import static org.hyperledger.fabric.sdk.helper.Utils.isNullOrEmpty;
import static org.hyperledger.fabric.sdk.helper.Utils.parseGrpcUrl;

/**
 * The Orderer class represents a orderer to which SDK sends deploy, invoke, or query requests.
 */
public class Orderer implements Serializable {
    public static final String ORDERER_ORGANIZATION_MSPID_PROPERTY = "org.hyperledger.fabric.sdk.orderer.organization_mspid";
    private static final Config config = Config.getConfig();
    private static final Log logger = LogFactory.getLog(Orderer.class);
    private static final long serialVersionUID = 4281642068914263247L;
    private final Properties properties;
    private final String name;
    private final String url;
    private transient boolean shutdown = false;
    private Channel channel;
    private transient volatile OrdererClient ordererClient = null;
    private transient byte[] clientTLSCertificateDigest;
    private String channelName = "";
    private transient String id = config.getNextID();

    Orderer(String name, String url, Properties properties) throws InvalidArgumentException {

        if (isNullOrEmpty(name)) {
            throw new InvalidArgumentException("Invalid name for orderer");
        }
        Exception e = checkGrpcUrl(url);
        if (e != null) {
            throw new InvalidArgumentException(e);
        }

        this.name = name;
        this.url = url;
        this.properties = properties == null ? new Properties() : (Properties) properties.clone(); //keep our own copy.
        logger.trace("Created " + toString());

    }

    static Orderer createNewInstance(String name, String url, Properties properties) throws InvalidArgumentException {
        return new Orderer(name, url, properties);

    }

    byte[] getClientTLSCertificateDigest() {
        if (null == clientTLSCertificateDigest) {
            clientTLSCertificateDigest = Endpoint.createEndpoint(url, properties).getClientTLSCertificateDigest();
        }
        return clientTLSCertificateDigest;
    }

    /**
     * Get Orderer properties.
     *
     * @return properties
     */

    public Properties getProperties() {

        return properties == null ? null : (Properties) properties.clone();
    }

    /**
     * Return Orderer's name
     *
     * @return orderer's name.
     */
    public String getName() {
        return name;
    }

    /**
     * getUrl - the Grpc url of the Orderer
     *
     * @return the Grpc url of the Orderer
     */
    public String getUrl() {
        return url;
    }

    void unsetChannel() {

        logger.debug(format("%s unsetting channel", toString()));

        channel = null;
        channelName = "";

    }

    /**
     * Get the channel of which this orderer is a member.
     *
     * @return {Channel} The channel of which this orderer is a member.
     */
    Channel getChannel() {
        return channel;
    }

    void setChannel(Channel channel) throws InvalidArgumentException {
        if (channel == null) {
            throw new InvalidArgumentException("setChannel Channel can not be null");
        }

        if (null != this.channel && this.channel != channel) {
            throw new InvalidArgumentException(format("Can not add orderer %s to channel %s because it already belongs to channel %s.",
                    name, channel.getName(), this.channel.getName()));
        }
        logger.debug(format("%s setting channel %s", toString(), channel));

        this.channel = channel;
        this.channelName = channel.getName();
        toString = null; //recalculate

    }

    /**
     * Send transaction to Order
     *
     * @param transaction transaction to be sent
     */

    Ab.BroadcastResponse sendTransaction(Common.Envelope transaction) throws Exception {
        if (shutdown) {
            throw new TransactionException(format("Orderer %s was shutdown.", name));
        }

        logger.debug(format("Orderer.sendTransaction %s", toString()));

        OrdererClient localOrdererClient = getOrdererClient();

        try {
            return localOrdererClient.sendTransaction(transaction);
        } catch (Throwable t) {
            removeOrdererClient(true);
            throw t;

        }

    }

    DeliverResponse[] sendDeliver(Common.Envelope transaction) throws TransactionException {

        if (shutdown) {
            throw new TransactionException(format("Orderer %s was shutdown.", name));
        }

        OrdererClient localOrdererClient = getOrdererClient();

        logger.debug(format("%s Orderer.sendDeliver", toString()));

        try {

            return localOrdererClient.sendDeliver(transaction);
        } catch (Throwable t) {
            logger.error(format("%s removing %s due to %s", this.toString(), localOrdererClient, t.getMessage()));
            removeOrdererClient(true);
            throw t;

        }

    }

    private synchronized OrdererClient getOrdererClient() {
        OrdererClient localOrdererClient = ordererClient;

        if (localOrdererClient == null || !localOrdererClient.isChannelActive()) {
            logger.trace(format("Channel %s creating new orderer client %s", channelName, this.toString()));
            localOrdererClient = new OrdererClient(this, Endpoint.createEndpoint(url, properties).getChannelBuilder(), properties);
            ordererClient = localOrdererClient;

        }
        return localOrdererClient;

    }

    private synchronized void removeOrdererClient(boolean force) {
        OrdererClient localOrderClient = ordererClient;
        ordererClient = null;

        if (null != localOrderClient) {
            logger.debug(format("Channel %s removing orderer client %s, isActive: %b", channelName, toString(), localOrderClient.isChannelActive()));
            try {
                localOrderClient.shutdown(force);
            } catch (Exception e) {
                logger.error(toString() + " error message: " + e.getMessage());
                logger.trace(e);
            }

        }
    }

    synchronized void shutdown(boolean force) {
        if (shutdown) {
            return;
        }
        shutdown = true;
        logger.debug(format("Shutting down %s", toString()));

        removeOrdererClient(true);
        channel = null;
        channelName = "";

    }

    private String endPoint;

    String getEndpoint() {
        if (null == endPoint) {
            Properties properties = parseGrpcUrl(url);
            endPoint = properties.get("host") + ":" + properties.getProperty("port").toLowerCase().trim();
        }
        return endPoint;
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            logger.trace("finalize " + toString());
            shutdown(true);
        } finally {
            super.finalize();
        }
    }

    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        id = config.getNextID();
    }

    private transient String toString;

    @Override
    public String toString() {
        String ltoString = toString;
        if (ltoString == null) {
            String mspid = "";

            if (properties != null && !isNullOrEmpty(properties.getProperty(ORDERER_ORGANIZATION_MSPID_PROPERTY))) {
                mspid = ", mspid: " + properties.getProperty(ORDERER_ORGANIZATION_MSPID_PROPERTY);
            }

            ltoString = "Orderer{id: " + id + ", channelName: " + channelName + ", name:" + name + ", url: " + url + mspid + "}";
            toString = ltoString;
        }
        return ltoString;
    }
} // end Orderer
