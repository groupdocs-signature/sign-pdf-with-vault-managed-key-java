# Signing PDFs in Java with a Vault-Managed Key

[![Product Page](https://img.shields.io/badge/Product%20Page-2865E0?style=for-the-badge&logo=appveyor&logoColor=white)](https://products.groupdocs.com/signature/java/)
[![Docs](https://img.shields.io/badge/Docs-2865E0?style=for-the-badge&logo=Hugo&logoColor=white)](https://docs.groupdocs.com/signature/java/)
[![Blog](https://img.shields.io/badge/Blog-2865E0?style=for-the-badge&logo=WordPress&logoColor=white)](https://blog.groupdocs.com/categories/groupdocs.signature-product-family/)
[![Free Support](https://img.shields.io/badge/Free%20Support-2865E0?style=for-the-badge&logo=Discourse&logoColor=white)](https://forum.groupdocs.com/c/signature/13)
[![Temporary License](https://img.shields.io/badge/Temporary%20License-2865E0?style=for-the-badge&logo=rocket&logoColor=white)](https://purchase.groupdocs.com/temp-license/100124)

## Introduction

External signing is a GroupDocs.Signature capability for Java that hands the document digest
to a callback you provide instead of signing with a private key the application loads. This
sample points that callback at the HashiCorp Vault Transit engine. The RSA key is created
inside Vault, the JVM never holds it, and the only value that travels is a 32-byte SHA-256
digest. The output is a normal signed PDF with a visible signature box.

Everything runs locally: a dev-mode Vault container from the included `docker-compose.yml`,
then `mvn compile exec:java`. The sample was built and run with GroupDocs.Signature for Java
26.10, BouncyCastle 1.86 and Maven 3.9, on JDK 25 under Windows and JDK 17 under Linux.

## Use Case Scenarios

A document service that signs statements or agreements on a schedule, where the security team
will not accept a certificate file on the application host. A regulated environment that
requires every signing operation to leave an audit record. A migration away from a shared PFX
that three teams have a copy of. Or a step before a hardware module: the same callback talks to
an HSM or a cloud KMS without any other change to the signing code.

## The Problem

Handing a PDF library a PFX file and its password is the usual approach, and it puts a copy of
the private key wherever the application runs. The copy then spreads: into the container image,
the build pipeline, the backup, the laptop that once debugged production. Everyone holding one
can sign in the organisation's name until the certificate is revoked.

Tightening the file permissions does not change the shape of the problem. At the moment of
signing the key is in the JVM's memory, so a heap dump still exposes it. What a review actually
asks for is a key that cannot be read at all, together with a record of each time it was used.

### Common Challenges

Delegating the cryptography only works if the signing library supports it. A library that
insists on loading a `PrivateKey` cannot talk to a key manager at all, and most PDF tooling for
Java is built that way. The second challenge is the certificate: a PDF signature carries one, a
non-exportable key has none, and nothing in the JDK builds a certificate whose signature comes
from somewhere else.

## The Solution

`DigitalSignOptions.setCustomSignHash` takes the callback. GroupDocs.Signature prepares the
PDF, determines the signed byte range, hashes it, and calls the callback with that digest. The
callback returns signature bytes; the library embeds them with the certificate and writes the
file. Vault Transit fits the other side exactly, because it signs a digest and does not want the
document.

For the certificate, BouncyCastle's `X509v3CertificateBuilder` accepts a `ContentSigner`, which
is an interface with one job: produce the signature over bytes it was given. Implementing it
against Vault gives a certificate built around the Vault public key and signed by Vault itself.

## Implementation Workflow

1. Read the Transit key: its latest version and public key. Create the key on the first run.
2. Build an X.509 certificate for that public key, with Vault signing the certificate.
3. Sign the PDF, with GroupDocs.Signature calling back into the Vault signer for the digest.
4. Verify the signed PDF against the same certificate before anything is written out.

Steps 2 and 3 each cause exactly one `transit/sign` request, both pinned to the same key
version.

## Requirements

- **JDK** - 8 or later; tested on JDK 25 (Windows) and JDK 17 (Linux)
- **Maven** - 3.x; the first build downloads the GroupDocs.Signature jar, about 220 MB
- **Docker** - for the dev-mode Vault container
- **Fonts on Linux** - Arial, because the visible signature is drawn with it; without it signing
  fails with "Font Arial was not found"
- **Licence** - optional; evaluation mode accepts documents of up to 2 pages, and the included
  `document.pdf` has one

## Project Structure

```
sign-pdf-with-vault-managed-key-java/
|
├── pom.xml                                  GroupDocs.Signature, BouncyCastle, Gson
├── docker-compose.yml                       Vault in dev mode, local only
├── vault/sample-signer.hcl                  least-privilege policy example
├── Resources/document.pdf                   input document
└── src/main/java/com/groupdocs/samples/vault/
    ├── SignPdfWithVault.java                entry point: key, certificate, sign, verify
    ├── VaultSigner.java                     the callback GroupDocs.Signature invokes
    ├── CertificateHelper.java               BouncyCastle certificate signed by Vault
    ├── VaultTransitClient.java              Vault Transit HTTP calls
    ├── VaultKey.java                        key version and public key
    └── VaultException.java                  Vault error with its status code
```

`SignPdfWithVault` holds the whole run and prints each step. `VaultSigner` is the integration
surface and nothing else: one method and an algorithm map. `CertificateHelper` contains the
`ContentSigner` that lets BouncyCastle delegate to Vault. `VaultTransitClient` speaks HTTP with
`HttpURLConnection` and Gson, so the only third-party pieces are the signing library and
BouncyCastle.

## Practical Examples

### Use Case: the callback GroupDocs.Signature invokes

```java
public byte[] customSignHash(
        byte[] signableHash, int hashAlgorithm, SignatureContext signatureContext)
        throws Exception {
    return vault.signHash(
        keyName, keyVersion, signableHash, toVaultHashAlgorithm(hashAlgorithm));
}
```

`signableHash` is the digest of the PDF's signed byte range, 32 bytes for SHA-256, and it is
exactly what the signature must cover. `hashAlgorithm` arrives as an `int` constant from
`HashAlgorithm`, the algorithm the library really used, so it maps one to one onto Vault's
names: `Sha256` to `sha2-256`, `Sha384` to `sha2-384`, `Sha512` to `sha2-512`, `Sha1` to
`sha1`. Anything else throws `IllegalArgumentException` rather than guessing. `keyVersion` is
fixed at construction, which is what keeps the signature and the certificate on the same key.

### Use Case: wiring the callback into the sign options

```java
DigitalSignature digitalSignature = new DigitalSignature();
digitalSignature.setX509Certificate(certificate);

DigitalSignOptions options = new DigitalSignOptions();
options.setSignature(digitalSignature);
options.setCustomSignHash(signer::customSignHash);
options.setHashAlgorithm(HashAlgorithm.Sha256);
options.setReason("Document signed with HashiCorp Vault Transit");
options.setLocation("HashiCorp Vault");

ByteArrayOutputStream signedPdf = new ByteArrayOutputStream();
Signature signature = new Signature(inputPdf.toString());
try {
    signature.sign(signedPdf, options);
} finally {
    signature.dispose();
}
Files.write(outputPdf, trimTrailingZeros(signedPdf.toByteArray()));
```

Three details are specific to Java and to this version. The callback goes in as a method
reference, `signer::customSignHash`, because the `ICustomSignHash` method carries an obfuscated
name in the 26.10 jar and cannot be implemented by name. The certificate is set with
`setX509Certificate` and holds only a public key, so nothing tries to sign locally. And the
document is signed into memory and written only on success, so a Vault refusal leaves no
half-written PDF on disk.

### Use Case: letting BouncyCastle sign through Vault

```java
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
```

BouncyCastle writes the to-be-signed certificate bytes into the stream from
`getOutputStream()`, then calls `getSignature()`. The digest is computed here and only the
digest leaves the process. `ContentSigner` declares no checked exceptions, so a Vault failure
travels out as `UncheckedIOException` and `createSelfSignedCertificate` unwraps it back into the
original `IOException` - without that, a 403 from Vault would surface as an unrelated runtime
error.

### Use Case: verification

```java
Signature signature = new Signature(signedPdf.toString());
try {
    return signature.verify(new DigitalVerifyOptions(certificateFile.toString()))
        .isValid();
} finally {
    signature.dispose();
}
```

In 26.10 the certificate has to be passed to `DigitalVerifyOptions` as a file path; the stream
form throws a `NullPointerException`. That is why the sample writes the certificate to
`Result/vault-signer.cer` and verifies against the file. `isValid()` is false when the document
changed after signing, or when the signature came from a key version other than the one in the
certificate.

## Which version quirks should I know before porting this?

Four, all in 26.10. The `ICustomSignHash` method name is obfuscated, so pass a method
reference. The signed output arrives with trailing zero bytes outside the signature, so trim
them. `DigitalVerifyOptions` needs a certificate file, not a stream. And the visible signature
needs Arial present, which bare Linux images do not have.

## Benefits

The private key has no copy outside Vault, so there is nothing on the application host to steal,
rotate out of sync, or forget in a backup. The signing service runs with a token scoped to two
operations, and `vault/sample-signer.hcl` in this repository is that policy; with it, rotating or
creating keys returns `403 permission denied` while signing continues to work.

Every signature becomes a Vault request, so enabling an audit device produces the evidence an
auditor asks for without reconstructing it from application logs. Key rotation happens in one
place, and because the signer pins a version, a rotation cannot quietly split the certificate
from the signature.

The same callback works against an HSM or a cloud KMS. I ported this build from the .NET and
Python versions of the same sample, and the Vault request body came across unchanged - only the
certificate construction and the four quirks above are Java's own.

## Related Use Cases and Resources

For more about digital signatures with GroupDocs.Signature for Java, these pages go further:

* **Keep the Signing Key in Vault: the Full Java Walkthrough** - the same build explained from
  the old PFX approach to the finished pipeline:
  [Read the article](https://blog.groupdocs.com/signature/sign-pdf-with-hashicorp-vault-transit-java/)

* **Five Methods for Signing PDFs with a Vault-Held Key in Java** - the method-by-method guide
  with the considerations for each:
  [Read the article](https://docs.groupdocs.com/signature/java/use-cases/sign-pdf-with-hashicorp-vault-transit/)

* **Certificate Validity, Digests and Logging in Java Signing** - expiry rules, SHA-2 choice and
  log levels when signing with a certificate:
  [Read the article](https://docs.groupdocs.com/signature/java/use-cases/certificate-validity-hash-and-logging/)

* **eSign a Document with a Digital Signature in Java** - the standard PFX-based path, for
  comparison with the external signer here:
  [Read the article](https://docs.groupdocs.com/signature/java/esign-document-with-digital-signature/)

* **Verify Digital Signatures in a Document with Java** - the verification API in full:
  [Read the article](https://docs.groupdocs.com/signature/java/verify-digital-signatures-in-the-document/)

* **Iterative Digital Signing of a PDF Document** - adding a second signature without breaking
  the first:
  [Read the article](https://docs.groupdocs.com/signature/java/iterative-digital-signing-of-the-pdf-document/)

## Keywords

`hashicorp vault`, `vault transit`, `custom sign hash`, `external signing`, `pdf digital
signature`, `java digital signature`, `key management`, `groupdocs signature`, `x.509
certificate`, `bouncycastle`, `contentsigner`, `key rotation`, `prehashed signing`,
`private key protection`, `least privilege`, `pkcs1v15`, `rsa 2048`, `sha-256`, `maven`,
`pdf signing`

## Support

For technical support, visit:
- [Free Support Forum](https://forum.groupdocs.com/c/signature/13)
- [Product Documentation](https://docs.groupdocs.com/signature/java/)
- [API Reference](https://reference.groupdocs.com/signature/java/)
- [Get Temporary License](https://purchase.groupdocs.com/temp-license/100124)
