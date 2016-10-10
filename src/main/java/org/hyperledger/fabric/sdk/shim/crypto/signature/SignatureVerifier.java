package org.hyperledger.fabric.sdk.shim.crypto.signature;

public interface SignatureVerifier {
    boolean verify(byte[] publicKey, byte[] signature, byte[] payload);
}
