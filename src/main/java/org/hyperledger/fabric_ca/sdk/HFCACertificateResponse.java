package org.hyperledger.fabric_ca.sdk;

import java.util.Collection;

/**
 * The response from a certificate API request, contains the status code of the
 * request and certificates that were retrieved
 */
public class HFCACertificateResponse {
    private final int statusCode;
    private final Collection<HFCACredential> certs;

    /**
     * Contains the response from the server with status code and credentials requested
     *
     * @param statusCode Status code of the HTTP request
     * @param certs The certificates return from the GET request
     */
    HFCACertificateResponse(int statusCode, Collection<HFCACredential> certs) {
        this.statusCode = statusCode;
        this.certs = certs;
    }

    /**
     * Returns the status code of the request
     *
     * @return HTTP status code
     */
    public int getStatusCode() {
        return statusCode;
    }

    /**
     * Returns the certificates that were retrieved from the GET certificate request
     *
     * @return Certificates
     */
    public Collection<HFCACredential> getCerts() {
        return certs;
    }
}
