package org.hyperledger.fabric_ca.sdk;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.hyperledger.fabric_ca.sdk.exception.HFCACertificateException;

/**
 * An x509 credential
 */
public class HFCAX509Certificate extends HFCACredential {
    private String pem;
    private X509Certificate x509Cert;

    // serial and aki together form a unique identifier for a certificate
    private BigInteger serial;
    private AuthorityKeyIdentifier aki;

    HFCAX509Certificate(String pem) throws CertificateException, HFCACertificateException {
        this.pem = pem;
        this.x509Cert = getX509Certificate();
        this.serial = getSerial();
        this.aki = getAKI();
    }

    public String getPEM() {
        return pem;
    }

    public X509Certificate getX509() {
        return x509Cert;
    }

    private X509Certificate getX509Certificate() throws CertificateException, HFCACertificateException {
        if (pem == null) {
            throw new HFCACertificateException("Certificate PEM is null");
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(pem.getBytes()));
    }

    private BigInteger getSerial() throws HFCACertificateException {
        if (x509Cert == null) {
            throw new HFCACertificateException("Certificate is null");
        }
        return x509Cert.getSerialNumber();
    }

    private AuthorityKeyIdentifier getAKI() throws HFCACertificateException {
        if (x509Cert == null) {
            throw new HFCACertificateException("Certificate is null");
        }
        byte[] fullExtValue = x509Cert.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        byte[] extValue = ASN1OctetString.getInstance(fullExtValue).getOctets();
        return AuthorityKeyIdentifier.getInstance(extValue);
    }
}