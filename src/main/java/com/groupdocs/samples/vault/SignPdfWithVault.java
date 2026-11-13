package com.groupdocs.samples.vault;

import com.groupdocs.signature.Signature;
import com.groupdocs.signature.domain.Padding;
import com.groupdocs.signature.domain.enums.HashAlgorithm;
import com.groupdocs.signature.domain.enums.HorizontalAlignment;
import com.groupdocs.signature.domain.enums.VerticalAlignment;
import com.groupdocs.signature.domain.signatures.DigitalSignature;
import com.groupdocs.signature.licensing.License;
import com.groupdocs.signature.options.sign.DigitalSignOptions;
import com.groupdocs.signature.options.verify.DigitalVerifyOptions;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * Signs a PDF with GroupDocs.Signature while the private key stays in HashiCorp Vault.
 * GroupDocs.Signature computes the PDF digest and calls {@link VaultSigner}, which gets
 * the digest signed by the Vault Transit engine. The key never leaves Vault.
 */
public final class SignPdfWithVault {
    // Defaults for the local Vault from docker-compose.yml (dev mode only). Set VAULT_ADDR
    // and VAULT_TOKEN to use another Vault or a less powerful token.
    private static final String DEFAULT_VAULT_ADDRESS = "http://localhost:8200";
    private static final String DEFAULT_VAULT_TOKEN = "dev-only-token";
    private static final String KEY_NAME = "pdf-signing-key";

    private SignPdfWithVault() {
    }

    public static void main(String[] args) {
        System.exit(run());
    }

    private static int run() {
        setLicense("REPLACE_WITH_YOUR_LICENSE_PATH");

        Path inputPdf = Paths.get("Resources", "document.pdf").toAbsolutePath();
        Path outputPdf = Paths.get("Result", "signed_document.pdf").toAbsolutePath();
        Path certificateFile = Paths.get("Result", "vault-signer.cer").toAbsolutePath();
        if (!Files.isRegularFile(inputPdf)) {
            System.out.println("ERROR: input PDF not found: " + inputPdf);
            return 1;
        }

        String vaultAddress = envOrDefault("VAULT_ADDR", DEFAULT_VAULT_ADDRESS);
        String vaultToken = envOrDefault("VAULT_TOKEN", DEFAULT_VAULT_TOKEN);

        try {
            System.out.println("Vault: " + vaultAddress);
            VaultTransitClient vault = new VaultTransitClient(vaultAddress, vaultToken);

            VaultKey key = getOrCreateKey(vault);
            System.out.println(
                "Signing key: '" + KEY_NAME + "', version " + key.getVersion());

            System.out.println("Creating a self-signed certificate for the Vault key "
                + "(signed by Vault)...");
            X509Certificate certificate =
                CertificateHelper.createSelfSignedCertificate(vault, KEY_NAME, key);

            System.out.println("Signing '" + inputPdf.getFileName() + "' "
                + "(the digest goes to Vault, the key stays there)...");
            signPdf(inputPdf, outputPdf, certificate,
                new VaultSigner(vault, KEY_NAME, key.getVersion()));
            System.out.println("Signed PDF: " + outputPdf);

            Files.write(certificateFile, certificate.getEncoded());
            boolean isValid = verifyPdf(outputPdf, certificateFile);
            System.out.println("Signature valid: " + isValid);
            return isValid ? 0 : 1;
        } catch (Exception e) {
            // GroupDocs errors can carry more lines, and an error from the signer comes
            // with its class name in front: keep the first line, drop the class name.
            String message = e.getMessage() == null ? e.toString() : e.getMessage();
            String firstLine = message.split("\\R")[0];
            System.out.println(
                "ERROR: " + firstLine.replaceFirst("^[\\w.$]+(Exception|Error): ", ""));
            return 1;
        }
    }

    private static void setLicense(String licensePath) {
        if (new File(licensePath).isFile()) {
            new License().setLicense(licensePath);
        } else {
            System.out.println("No licence file found: running in evaluation mode "
                + "(documents of up to 2 pages).");
        }
    }

    /**
     * Reads the signing key from Vault Transit and creates it first if it does not exist
     * yet.
     *
     * @remarks
     * No GroupDocs API here; this prepares the key that the PDF signature will use. It
     * calls {@link VaultTransitClient#readKey} ({@code GET /v1/transit/keys/{name}}). If
     * Vault answers 404 (no such key, or Transit not enabled), it enables Transit, creates
     * an RSA-2048 key and reads it again. The result is the key's latest version and its
     * public key in PEM.
     *
     * <p>Reading first matters for least privilege: a token that may only read the key
     * and sign with it (policy {@code vault/sample-signer.hcl}) skips the setup and never
     * needs admin rights. Without such rights the setup calls fail with 403, which is the
     * expected answer.
     *
     * <p>In production an administrator creates the key once; the sample does it here so
     * that the local demo works out of the box.
     *
     * @param vault Vault Transit client with the address and token to use
     * @return the latest key version and its public key
     * @throws IOException if Vault cannot be reached or refuses a request
     */
    private static VaultKey getOrCreateKey(VaultTransitClient vault) throws IOException {
        VaultKey key = vault.readKey(KEY_NAME);
        if (key != null) {
            return key;
        }

        System.out.println("Key '" + KEY_NAME + "' not found: enabling Transit and "
            + "creating an RSA-2048 key (one-time setup)...");
        vault.enableTransit();
        vault.createKey(KEY_NAME, "rsa-2048");
        key = vault.readKey(KEY_NAME);
        if (key == null) {
            throw new IllegalStateException(
                "Key '" + KEY_NAME + "' was not found after it was created.");
        }
        return key;
    }

    /**
     * Signs a PDF with a digital signature whose private key stays in HashiCorp Vault.
     *
     * @remarks
     * Uses {@link Signature#sign(java.io.OutputStream,
     * com.groupdocs.signature.options.sign.SignOptions)} with {@link DigitalSignOptions}.
     * GroupDocs.Signature prepares the PDF, computes the SHA-256 digest of the signed byte
     * range and calls the custom signer, here {@link VaultSigner#customSignHash} that gets
     * the digest signed by Vault. GroupDocs then embeds the signature and the certificate.
     * Input: a PDF path; output: the signed PDF at {@code outputPdf}.
     *
     * <p>Notable options:
     * <ul>
     * <li>{@code DigitalSignature.setX509Certificate(certificate)}: the certificate holds
     * only the public key and no private key is set; the custom signer does the
     * signing.</li>
     * <li>{@code setCustomSignHash(signer::customSignHash)}: a method reference, because
     * in the 26.10 jar the {@code ICustomSignHash} method has an obfuscated name.</li>
     * <li>{@code setHashAlgorithm(Sha256)}: also the default for PDF.</li>
     * <li>{@code setVisible(true)} with bottom/right alignment and a margin: a 300 x 80 pt
     * box in the bottom-right corner with signer, date, reason, location and contact. It
     * is drawn with the font Arial; on Linux without Arial signing fails with "Font Arial
     * was not found".</li>
     * </ul>
     *
     * <p>Edge cases: the document is signed into memory and written only on success, so
     * a failed sign (for example Vault refuses with 403) leaves no half-written file.
     * Version 26.10 pads the signed output with zero bytes after the end of the PDF; they
     * are not covered by the signature, and the method cuts them off. The signing time is
     * the local time without a time zone (Java {@code Date} has none). Without a
     * licence, evaluation mode refuses documents of more than 2 pages.
     *
     * <p>Use this pattern when the signing key must stay in a key manager (Vault, an HSM,
     * a cloud KMS) and the application may only ask for signatures.
     *
     * @param inputPdf path of the PDF to sign
     * @param outputPdf path of the signed PDF to write
     * @param certificate certificate with the Vault public key (no private key)
     * @param signer the external signer that GroupDocs.Signature calls
     * @throws Exception if signing fails, including errors from the signer
     */
    private static void signPdf(
            Path inputPdf, Path outputPdf, X509Certificate certificate, VaultSigner signer)
            throws Exception {
        // The certificate holds only the public key; the custom signer does the signing.
        DigitalSignature digitalSignature = new DigitalSignature();
        digitalSignature.setX509Certificate(certificate);

        DigitalSignOptions options = new DigitalSignOptions();
        options.setSignature(digitalSignature);
        options.setCustomSignHash(signer::customSignHash);
        options.setHashAlgorithm(HashAlgorithm.Sha256);
        // Visible box in the bottom-right corner, wide enough for the Reason line
        options.setVisible(true);
        options.setVerticalAlignment(VerticalAlignment.Bottom);
        options.setHorizontalAlignment(HorizontalAlignment.Right);
        Padding margin = new Padding();
        margin.setBottom(60);
        margin.setRight(50);
        options.setMargin(margin);
        options.setWidth(300);
        options.setHeight(80);
        options.setReason("Document signed with HashiCorp Vault Transit");
        options.setContact("vault-signer@example.com");
        options.setLocation("HashiCorp Vault");

        // Sign into memory and write the file only on success: no half-written PDF.
        ByteArrayOutputStream signedPdf = new ByteArrayOutputStream();
        Signature signature = new Signature(inputPdf.toString());
        try {
            signature.sign(signedPdf, options);
        } finally {
            signature.dispose();
        }
        Files.createDirectories(outputPdf.getParent());
        Files.write(outputPdf, trimTrailingZeros(signedPdf.toByteArray()));
    }

    /**
     * Verifies the signed PDF against the certificate that was used to sign it.
     *
     * @remarks
     * Uses {@link Signature#verify} with {@link DigitalVerifyOptions} built from the
     * certificate file (DER, the public part only). Input: the signed PDF path and the
     * certificate path; output: {@code VerificationResult.isValid()}. In 26.10 the
     * certificate must be passed as a file path: the stream form throws a
     * NullPointerException.
     *
     * <p>The check is cryptographic: it is {@code false} when the document was changed
     * after signing or when the signature was made with another key, for example a
     * different Vault key version than the one in the certificate.
     *
     * <p>A self-signed certificate is enough for this check. PDF readers such as Adobe
     * Acrobat additionally look for a trusted issuer and report the signer's identity as
     * unknown.
     *
     * @param signedPdf path of the signed PDF
     * @param certificateFile the certificate that was used for signing, as a .cer file
     * @return {@code true} if the signature is valid for this certificate
     * @throws Exception if the document cannot be read
     */
    private static boolean verifyPdf(Path signedPdf, Path certificateFile)
            throws Exception {
        Signature signature = new Signature(signedPdf.toString());
        try {
            return signature.verify(new DigitalVerifyOptions(certificateFile.toString()))
                .isValid();
        } finally {
            signature.dispose();
        }
    }

    // 26.10 writes the signed PDF followed by zero bytes (outside the signed byte range).
    private static byte[] trimTrailingZeros(byte[] pdf) {
        int end = pdf.length;
        while (end > 0 && pdf[end - 1] == 0) {
            end--;
        }
        return Arrays.copyOf(pdf, end);
    }

    private static String envOrDefault(String name, String defaultValue) {
        String value = System.getenv(name);
        return value == null || value.isEmpty() ? defaultValue : value;
    }
}
