package org.hyperledger.fabric_ca.sdk;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.hyperledger.fabric_ca.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric_ca.sdk.helper.Util;

/**
 * Request to the Fabric CA server to get certificates
 * based on filter parameters
 */
public class HFCACertificateRequest {

    private final Map<String, String> queryParms = new HashMap<>();

    /**
     * Get certificate request from Fabric CA server
     */
    HFCACertificateRequest() {
    }

    /**
     * Get certificates for this enrollment ID
     *
     * @param enrollmentID Enrollment ID associated with the certificate(s)
     */
    public void setEnrollmentID(String enrollmentID) {
        queryParms.put("id", enrollmentID);
    }

    /**
     * Get certificates for this serial number
     *
     * @param serial Serial Number of the certificate
     */
    public void setSerial(String serial) {
        queryParms.put("serial", serial);
    }

    /**
     * Get certificates for this aki
     *
     * @param aki AKI of the certificate(s)
     */
    public void setAki(String aki) {
        queryParms.put("aki", aki);
    }

    /**
     * Get certificates that have been revoked after this date
     *
     * @param revokedStart Revoked after date
     * @throws InvalidArgumentException Date can't be null
     */
    public void setRevokedStart(Date revokedStart) throws InvalidArgumentException {
        if (revokedStart == null) {
            throw new InvalidArgumentException("Date can't be null");
        }
        queryParms.put("revoked_start", Util.dateToString(revokedStart));
    }

    /**
     * Get certificates that have been revoked before this date
     *
     * @param revokedEnd Revoked before date
     * @throws InvalidArgumentException Date can't be null
     */
    public void setRevokedEnd(Date revokedEnd) throws InvalidArgumentException {
        if (revokedEnd == null) {
            throw new InvalidArgumentException("Date can't be null");
        }
        queryParms.put("revoked_end", Util.dateToString(revokedEnd));
    }

    /**
     * Get certificates that have expired after this date
     *
     * @param expiredStart Expired after date
     * @throws InvalidArgumentException Date can't be null
     */
    public void setExpiredStart(Date expiredStart) throws InvalidArgumentException {
        if (expiredStart == null) {
            throw new InvalidArgumentException("Date can't be null");
        }
        queryParms.put("expired_start", Util.dateToString(expiredStart));
    }

    /**
     * Get certificates that have expired before this date
     *
     * @param expiredEnd Expired end date
     * @throws InvalidArgumentException Date can't be null
     */
    public void setExpiredEnd(Date expiredEnd) throws InvalidArgumentException {
        if (expiredEnd == null) {
            throw new InvalidArgumentException("Date can't be null");
        }
        queryParms.put("expired_end", Util.dateToString(expiredEnd));
    }

    /**
     * Get certificates that include/exclude expired certificates
     *
     * @param expired Boolean indicating if expired certificates should be excluded
     */
    public void setExpired(boolean expired) {
        if (expired) {
            queryParms.put("notexpired", "false");
        } else {
            queryParms.put("notexpired", "true");
        }
    }

    /**
     * Get certificates that include/exclude revoked certificates
     *
     * @param revoked Boolean indicating if revoked certificates should excluded
     */
    public void setRevoked(boolean revoked) {
        if (revoked) {
            queryParms.put("notrevoked", "false");
        } else {
            queryParms.put("notrevoked", "true");
        }
    }

    /**
     * Get all the filter parameters for this certificate request
     *
     * @return A map of filters that will be used as query parameters in GET request
     */
    public Map<String, String> getQueryParameters() {
        return this.queryParms;
    }

}
