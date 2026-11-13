package com.groupdocs.samples.vault;

/**
 * The latest version of a Transit key and its public key in PEM format.
 */
public final class VaultKey {
    private final int version;
    private final String publicKeyPem;

    public VaultKey(int version, String publicKeyPem) {
        this.version = version;
        this.publicKeyPem = publicKeyPem;
    }

    public int getVersion() {
        return version;
    }

    public String getPublicKeyPem() {
        return publicKeyPem;
    }
}
