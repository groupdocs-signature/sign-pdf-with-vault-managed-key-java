package com.groupdocs.samples.vault;

import com.groupdocs.signature.domain.enums.HashAlgorithm;
import com.groupdocs.signature.options.sign.signaturecontext.SignatureContext;

/**
 * Signs the digest that GroupDocs.Signature computed, with a key that stays in HashiCorp
 * Vault Transit.
 */
public final class VaultSigner {
    private final VaultTransitClient vault;
    private final String keyName;
    private final int keyVersion;

    /**
     * Creates a signer bound to one Vault Transit key version.
     *
     * @remarks
     * Pass the key version that the certificate was made for. A certificate holds one
     * public key, so if Vault signed with another version (for example the latest one
     * after a key rotation), the PDF would be written without any error but would not
     * verify.
     *
     * @param vault Vault Transit client used for the sign requests
     * @param keyName Transit key name
     * @param keyVersion key version in the signing certificate
     */
    public VaultSigner(VaultTransitClient vault, String keyName, int keyVersion) {
        this.vault = vault;
        this.keyName = keyName;
        this.keyVersion = keyVersion;
    }

    /**
     * Gets the digest of the PDF signed by Vault and returns the raw signature bytes.
     *
     * @remarks
     * This is the GroupDocs.Signature hook for external signing, with the shape of
     * {@code ICustomSignHash}: {@code (byte[] signableHash, int hashAlgorithm,
     * SignatureContext context)}. It is passed as a method reference,
     * {@code options.setCustomSignHash(signer::customSignHash)}, because in the 26.10 jar
     * the interface method has an obfuscated name. GroupDocs.Signature calls it once per
     * PDF signature. {@code signableHash} is already a digest of the PDF's signed bytes
     * (32 bytes for SHA-256), and it is exactly the value the signature must cover, so it
     * goes to Vault with {@code prehashed = true} and is never hashed again.
     *
     * <p>{@code hashAlgorithm} is a {@link HashAlgorithm} constant, the algorithm
     * GroupDocs.Signature really used, so it maps one to one to Vault names: Sha1 to
     * {@code sha1}, Sha256 to {@code sha2-256}, Sha384 to {@code sha2-384}, Sha512 to
     * {@code sha2-512}. Any other value throws {@link IllegalArgumentException}. SHA-1
     * works but is a legacy algorithm that validators may reject.
     *
     * <p>If Vault refuses (for example 403 for a token without sign rights), the exception
     * stops {@code Signature.sign}, which throws a {@code GroupDocsSignatureException}
     * that carries the original message.
     *
     * @param signableHash the digest computed by GroupDocs.Signature
     * @param hashAlgorithm the algorithm that produced the digest
     * @param signatureContext signing context from GroupDocs.Signature (not used)
     * @return the raw RSA PKCS#1 v1.5 signature over the digest
     * @throws Exception if Vault cannot be reached or refuses the request
     */
    public byte[] customSignHash(
            byte[] signableHash, int hashAlgorithm, SignatureContext signatureContext)
            throws Exception {
        return vault.signHash(
            keyName, keyVersion, signableHash, toVaultHashAlgorithm(hashAlgorithm));
    }

    private static String toVaultHashAlgorithm(int hashAlgorithm) {
        switch (hashAlgorithm) {
            case HashAlgorithm.Sha1:
                return "sha1";
            case HashAlgorithm.Sha256:
                return "sha2-256";
            case HashAlgorithm.Sha384:
                return "sha2-384";
            case HashAlgorithm.Sha512:
                return "sha2-512";
            default:
                throw new IllegalArgumentException(
                    "Hash algorithm " + hashAlgorithm + " is not supported.");
        }
    }
}
