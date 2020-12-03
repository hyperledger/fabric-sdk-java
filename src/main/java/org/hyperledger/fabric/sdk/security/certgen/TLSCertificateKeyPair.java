package org.hyperledger.fabric.sdk.security.certgen;

public interface TLSCertificateKeyPair {
    /***
     * @return the certificate, in PEM encoding
     */
    public byte[] getCertPEMBytes();

    /***
     * @return the certificate, in DER encoding
     */
    public byte[] getCertDERBytes();

    /***
     * @return the key, in PEM encoding
     */
    public byte[] getKeyPemBytes();
}
