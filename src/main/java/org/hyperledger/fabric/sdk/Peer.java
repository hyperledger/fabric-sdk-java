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

import java.util.Objects;
import java.util.Properties;

import com.google.common.util.concurrent.ListenableFuture;
import io.netty.util.internal.StringUtil;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.hyperledger.fabric.protos.peer.FabricProposal;
import org.hyperledger.fabric.protos.peer.FabricProposalResponse;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.exception.PeerException;

import static java.lang.String.format;
import static org.hyperledger.fabric.sdk.helper.Utils.checkGrpcUrl;

/**
 * The Peer class represents a peer to which SDK sends deploy, or query proposals requests.
 */
public class Peer {
    private static final Log logger = LogFactory.getLog(Peer.class);
    private volatile EndorserClient endorserClent;
    private final Properties properties;
    private final String name;
    private final String url;
    private boolean shutdown = false;
    private Channel channel;

    Peer(String name, String grpcURL, Properties properties) throws InvalidArgumentException {

        Exception e = checkGrpcUrl(grpcURL);
        if (e != null) {
            throw new InvalidArgumentException("Bad peer url.", e);

        }

        if (StringUtil.isNullOrEmpty(name)) {
            throw new InvalidArgumentException("Invalid name for peer");
        }

        this.url = grpcURL;
        this.name = name;
        this.properties = properties == null ? null : (Properties) properties.clone(); //keep our own copy.

    }

    /**
     * Peer's name
     *
     * @return return the peer's name.
     */

    public String getName() {

        return name;
    }

    public Properties getProperties() {

        return properties == null ? null : (Properties) properties.clone();
    }

    /**
     * Set the channel the peer is on.
     *
     * @param channel
     */

    void setChannel(Channel channel) throws InvalidArgumentException {

        if (null != this.channel) {
            throw new InvalidArgumentException(format("Can not add peer %s to channel %s because it already belongs to channel %s.",
                    name, channel.getName(), this.channel.getName()));
        }

        this.channel = channel;

    }

    void unsetChannel() {
        channel = null;

    }

    /**
     * The channel the peer is set on.
     *
     * @return
     */

    Channel getChannel() {

        return channel;

    }

    /**
     * Get the URL of the peer.
     *
     * @return {string} Get the URL associated with the peer.
     */
    public String getUrl() {

        return this.url;
    }

    /**
     * for use in list of peers comparisons , e.g. list.contains() calls
     *
     * @param otherPeer the peer instance to compare against
     * @return true if both peer instances have the same name and url
     */
    @Override
    public boolean equals(Object otherPeer) {
        if (this == otherPeer) {
            return true;
        }
        if (otherPeer == null) {
            return false;
        }
        if (!(otherPeer instanceof Peer)) {
            return false;
        }
        Peer p = (Peer) otherPeer;
        return Objects.equals(this.name, p.name) && Objects.equals(this.url, p.url);
    }

    @Override
    public int hashCode() {
        return Objects.hash(name, url);
    }

    ListenableFuture<FabricProposalResponse.ProposalResponse> sendProposalAsync(FabricProposal.SignedProposal proposal)
            throws PeerException, InvalidArgumentException {
        checkSendProposal(proposal);

        logger.debug(format("peer.sendProposalAsync name: %s, url: %s", name, url));

        EndorserClient localEndorserClient = endorserClent; //work off thread local copy.

        if (null == localEndorserClient || !localEndorserClient.isChannelActive()) {
            endorserClent = new EndorserClient(new Endpoint(url, properties).getChannelBuilder());
            localEndorserClient = endorserClent;
        }

        try {
            return localEndorserClient.sendProposalAsync(proposal);
        } catch (Throwable t) {
            endorserClent = null;
            throw t;
        }
    }

    FabricProposalResponse.ProposalResponse sendProposal(FabricProposal.SignedProposal proposal)
            throws PeerException, InvalidArgumentException {
        checkSendProposal(proposal);

        logger.debug(format("peer.sendProposalAsync name: %s, url: %s", name, url));

        EndorserClient localEndorserClient = endorserClent; //work off thread local copy.

        if (null == localEndorserClient || !localEndorserClient.isChannelActive()) {
            endorserClent = new EndorserClient(new Endpoint(url, properties).getChannelBuilder());
            localEndorserClient = endorserClent;
        }

        try {
            return localEndorserClient.sendProposal(proposal);
        } catch (Throwable t) {
            endorserClent = null;
            throw t;
        }
    }

    private void checkSendProposal(FabricProposal.SignedProposal proposal) throws PeerException, InvalidArgumentException {

        if (shutdown) {
            throw new PeerException(format("Peer %s was shutdown.", name));
        }
        if (proposal == null) {
            throw new PeerException("Proposal is null");
        }
        Exception e = checkGrpcUrl(url);
        if (e != null) {
            throw new InvalidArgumentException("Bad peer url.", e);

        }
    }

    static Peer createNewInstance(String name, String grpcURL, Properties properties) throws InvalidArgumentException {

        return new Peer(name, grpcURL, properties);
    }

    synchronized void shutdown(boolean force) {
        if (shutdown) {
            return;
        }
        shutdown = true;
        channel = null;

        EndorserClient lendorserClent = endorserClent;

        //allow resources to finalize

        endorserClent = null;

        if (lendorserClent == null) {
            return;
        }

        lendorserClent.shutdown(force);
    }

    @Override
    protected void finalize() throws Throwable {
        shutdown(true);
        super.finalize();
    }
} // end Peer
