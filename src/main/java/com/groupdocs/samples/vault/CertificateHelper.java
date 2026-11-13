package com.groupdocs.samples.vault;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Date;
import java.util.concurrent.TimeUnit;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;

/**
 * Builds a self-signed certificate for a Vault Transit key. The certificate carries the
 * Vault public key and is signed by Vault, so no private key exists outside Vault.
 *
 * @remarks
 * Good for a demo: PDF readers show the signature as intact but the signer as unknown.
 * In production use a certificate issued by a CA for the same key (see README).
 */
public final class CertificateHelper {
    private static final long ONE_DAY = TimeUnit.DAYS.toMillis(1);

    private CertificateHelper() {
    }

    /**
     * Creates a self-signed X.509 certificate for the given Vault key version, signed by
     * Vault.
     *
     * @remarks
     * No GroupDocs API here; the result is the certificate that
     * {@code DigitalSignature.setX509Certificate} puts into the PDF. A PDF reader checks
     * the signature with the public key from this certificate, so it must be the Vault
     * public key of the same version that signs.
     *
     * <p>Uses BouncyCastle {@link X509v3CertificateBuilder} with a {@link ContentSigner}
     * that hashes the certificate data locally (SHA-256) and gets the digest signed
     * through {@code transit/sign}. This is the first of two Vault sign requests per run;
     * the second one signs the PDF digest. Subject and issuer are
     * {@code CN=Vault Transit Signer}; key usage is digital signature; the certificate has
     * no private key.
     *
     * <p>It is valid from one day before now for one year. A PDF reader compares the
     * signing time with the start date; a certificate made a second before signing was
     * reported by Adobe Acrobat as "expired or not yet valid" on a machine two hours east
     * of UTC.
     *
     * <p>In production replace it with a CA-issued certificate for the same key: Transit
     * can sign a CSR ({@code transit/keys/{name}/csr}), or the Vault PKI engine can act as
     * a CA.
     *
     * @param vault Vault Transit client that signs the certificate
     * @param keyName Transit key name
     * @param key key version and public key read from Vault
     * @return the certificate, public key only
     * @throws IOException if Vault refuses to sign
     * @throws CertificateException if the signed certificate cannot be decoded
     */
    public static X509Certificate createSelfSignedCertificate(
            VaultTransitClient vault, String keyName, VaultKey key)
            throws IOException, CertificateException {
        X500Name subject = new X500Name("CN=Vault Transit Signer");
        // Valid from yesterday: a PDF reader compares the signing time with this date,
        // and a clock or time-zone difference must not make a fresh certificate
        // "not yet valid".
        long now = System.currentTimeMillis();
        X509v3CertificateBuilder builder = new X509v3CertificateBuilder(
            subject,
            new BigInteger(127, new SecureRandom()),
            new Date(now - ONE_DAY),
            new Date(now + 365 * ONE_DAY),
            subject,
            SubjectPublicKeyInfo.getInstance(pemToDer(key.getPublicKeyPem())));
        builder.addExtension(
            Extension.basicConstraints, false, new BasicConstraints(false));
        builder.addExtension(
            Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));

        try {
            return new JcaX509CertificateConverter().getCertificate(
                builder.build(new VaultContentSigner(vault, keyName, key.getVersion())));
        } catch (UncheckedIOException e) {
            throw e.getCause(); // the Vault error from VaultContentSigner
        }
    }

    private static byte[] pemToDer(String pem) {
        String base64 = pem.replaceAll("-----[A-Z ]+-----", "").replaceAll("\\s", "");
        return Base64.getDecoder().decode(base64);
    }

    /**
     * Lets BouncyCastle sign a certificate with a Vault Transit key: SHA-256 with RSA
     * PKCS#1 v1.5.
     */
    private static final class VaultContentSigner implements ContentSigner {
        private static final AlgorithmIdentifier SHA256_WITH_RSA =
            new DefaultSignatureAlgorithmIdentifierFinder().find("SHA256withRSA");

        private final ByteArrayOutputStream data = new ByteArrayOutputStream();
        private final VaultTransitClient vault;
        private final String keyName;
        private final int keyVersion;

        VaultContentSigner(VaultTransitClient vault, String keyName, int keyVersion) {
            this.vault = vault;
            this.keyName = keyName;
            this.keyVersion = keyVersion;
        }

        @Override
        public AlgorithmIdentifier getAlgorithmIdentifier() {
            return SHA256_WITH_RSA;
        }

        @Override
        public OutputStream getOutputStream() {
            return data;
        }

        /**
         * Signs the certificate data with the Vault key: hashes it here and sends only the
         * digest.
         *
         * @remarks
         * BouncyCastle writes the to-be-signed certificate bytes to
         * {@link #getOutputStream()} and then calls this method. It computes their SHA-256
         * digest and calls {@link VaultTransitClient#signHash} ({@code prehashed},
         * PKCS#1 v1.5, pinned key version). The interface does not allow checked
         * exceptions, so a Vault error is wrapped in {@link UncheckedIOException}.
         *
         * @return the raw RSA signature from Vault
         */
        @Override
        public byte[] getSignature() {
            try {
                byte[] digest =
                    MessageDigest.getInstance("SHA-256").digest(data.toByteArray());
                return vault.signHash(keyName, keyVersion, digest, "sha2-256");
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }
    }
}
