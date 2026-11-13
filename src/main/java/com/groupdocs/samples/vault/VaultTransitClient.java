package com.groupdocs.samples.vault;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.JsonParser;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

/**
 * Minimal HTTP client for the HashiCorp Vault Transit secrets engine. API:
 * https://developer.hashicorp.com/vault/api-docs/secret/transit
 */
public final class VaultTransitClient {
    private final String address;
    private final String token;

    /**
     * Creates a client that sends every request to one Vault with one token.
     *
     * @remarks
     * The token goes in the {@code X-Vault-Token} header of every request. With the
     * local dev Vault from {@code docker-compose.yml} this is the root token
     * {@code dev-only-token}; a real application uses a short-lived token from an auth
     * method such as AppRole, limited by a policy to reading the key and signing with it.
     * Use HTTPS outside a local test.
     *
     * @param vaultAddress Vault address, for example {@code http://localhost:8200}
     * @param vaultToken Vault token used for all requests
     */
    public VaultTransitClient(String vaultAddress, String vaultToken) {
        this.address = vaultAddress.replaceAll("/+$", "");
        this.token = vaultToken;
    }

    /**
     * Reads the latest version of a Transit key and its public key.
     *
     * @remarks
     * Calls {@code GET /v1/transit/keys/{keyName}}. Vault returns a map of all key
     * versions with a {@code public_key} (PEM) for each, plus {@code latest_version}; this
     * method returns the latest one. The private key is never part of the answer.
     *
     * <p>Returns {@code null} when Vault answers 404: the key does not exist or Transit is
     * not enabled. Any other error (for example 403 when the token may not read the key)
     * throws {@link VaultException} with Vault's own message.
     *
     * <p>The version matters: a certificate holds one public key, so the same version must
     * be used for the certificate and for every sign request. After a key rotation the
     * latest version changes and so does its public key.
     *
     * @param keyName Transit key name
     * @return the latest version and its public key, or {@code null} if there is no key
     * @throws IOException if Vault cannot be reached or refuses the request
     */
    public VaultKey readKey(String keyName) throws IOException {
        JsonObject data;
        try {
            data = request("GET", "/v1/transit/keys/" + keyName, null)
                .getAsJsonObject("data");
        } catch (VaultException e) {
            if (e.getStatus() == 404) {
                return null;
            }
            throw e;
        }
        int version = data.get("latest_version").getAsInt();
        String publicKeyPem = data.getAsJsonObject("keys")
            .getAsJsonObject(String.valueOf(version)).get("public_key").getAsString();
        return new VaultKey(version, publicKeyPem);
    }

    /**
     * Enables the Transit secrets engine at {@code transit/}.
     *
     * @remarks
     * Calls {@code POST /v1/sys/mounts/transit} with {@code type = transit}. If Transit
     * is already enabled, Vault answers 400 "path is already in use"; that answer is
     * treated as success, any other error throws. This is an administrator action: it
     * needs a token with rights on {@code sys/mounts}, which the root dev token has and a
     * signing app should not have.
     *
     * @throws IOException if Vault cannot be reached or refuses the request
     */
    public void enableTransit() throws IOException {
        JsonObject body = new JsonObject();
        body.addProperty("type", "transit");
        try {
            request("POST", "/v1/sys/mounts/transit", body);
        } catch (VaultException e) {
            boolean alreadyEnabled = e.getStatus() == 400
                && e.getMessage().contains("path is already in use");
            if (!alreadyEnabled) {
                throw e;
            }
        }
    }

    /**
     * Creates a Transit key whose private part is generated inside Vault.
     *
     * @remarks
     * Calls {@code POST /v1/transit/keys/{keyName}} with the key type, for example
     * {@code rsa-2048}. The key is created with {@code exportable = false} (Vault's
     * default), so no API returns the private key: {@code transit/export/signing-key}
     * answers 400 "private key material is not exportable". Creating a key that already
     * exists returns the existing key unchanged. Like {@link #enableTransit()}, this is an
     * administrator action.
     *
     * @param keyName name of the new key
     * @param keyType Vault key type, for example {@code rsa-2048}
     * @throws IOException if Vault cannot be reached or refuses the request
     */
    public void createKey(String keyName, String keyType) throws IOException {
        JsonObject body = new JsonObject();
        body.addProperty("type", keyType);
        request("POST", "/v1/transit/keys/" + keyName, body);
    }

    /**
     * Signs an already computed digest with a Transit key and returns the raw RSA
     * signature.
     *
     * @remarks
     * Calls {@code POST /v1/transit/sign/{keyName}} with:
     * <ul>
     * <li>{@code prehashed = true}: the input is already a hash, so Vault signs it as it
     * is. Without it Vault hashes the digest again and the PDF signature does not
     * verify.</li>
     * <li>{@code signature_algorithm = pkcs1v15}: Vault's default for RSA keys is PSS, but
     * the PDF signature here is sha256WithRSAEncryption (PKCS#1 v1.5).</li>
     * <li>{@code key_version}: pins the signature to the key version in the
     * certificate.</li>
     * <li>{@code hash_algorithm}: Vault checks the digest length against it; a mismatch
     * fails with 500 "crypto/rsa: input must be hashed message".</li>
     * </ul>
     *
     * <p>Vault answers {@code vault:v{version}:{base64 signature}}; the method returns the
     * decoded signature bytes (256 bytes for RSA-2048). A token without {@code update} on
     * {@code transit/sign/{keyName}} gets 403, which throws {@link VaultException}.
     *
     * @param keyName Transit key name
     * @param keyVersion key version; the same version as in the certificate
     * @param digest the digest to sign
     * @param hashAlgorithm Vault name of the digest algorithm, e.g. "sha2-256"
     * @return the raw signature bytes
     * @throws IOException if Vault cannot be reached or refuses the request
     */
    public byte[] signHash(
            String keyName, int keyVersion, byte[] digest, String hashAlgorithm)
            throws IOException {
        JsonObject body = new JsonObject();
        body.addProperty("input", Base64.getEncoder().encodeToString(digest));
        body.addProperty("key_version", keyVersion);
        body.addProperty("hash_algorithm", hashAlgorithm);
        body.addProperty("prehashed", true);
        body.addProperty("signature_algorithm", "pkcs1v15");
        String signature = request("POST", "/v1/transit/sign/" + keyName, body)
            .getAsJsonObject("data").get("signature").getAsString();
        // Vault returns "vault:v<version>:<base64 signature>".
        return Base64.getDecoder().decode(
            signature.substring(signature.lastIndexOf(':') + 1));
    }

    /** Sends one request and throws {@link VaultException} with Vault's own error text. */
    private JsonObject request(String method, String path, JsonObject body)
            throws IOException {
        HttpURLConnection connection =
            (HttpURLConnection) new URL(address + path).openConnection();
        connection.setRequestMethod(method);
        connection.setConnectTimeout(10_000);
        connection.setReadTimeout(30_000);
        connection.setRequestProperty("X-Vault-Token", token);
        int status;
        try {
            if (body != null) {
                connection.setDoOutput(true);
                connection.setRequestProperty("Content-Type", "application/json");
                try (OutputStream output = connection.getOutputStream()) {
                    output.write(body.toString().getBytes(StandardCharsets.UTF_8));
                }
            }
            status = connection.getResponseCode();
        } catch (ConnectException e) {
            throw new VaultException(
                "Cannot reach Vault at " + address + ": " + e.getMessage(), 0);
        }

        String text = readText(status >= 400
            ? connection.getErrorStream() : connection.getInputStream());
        if (status >= 400) {
            throw new VaultException("Vault " + method + " " + path + " failed with "
                + status + ": " + errorText(text), status);
        }
        return text.isEmpty()
            ? new JsonObject() : JsonParser.parseString(text).getAsJsonObject();
    }

    private static String readText(InputStream stream) throws IOException {
        if (stream == null) {
            return "";
        }
        try (InputStream input = stream) {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[8192];
            for (int n; (n = input.read(chunk)) > 0; ) {
                buffer.write(chunk, 0, n);
            }
            return new String(buffer.toByteArray(), StandardCharsets.UTF_8);
        }
    }

    /** Joins Vault's error list into one line; keeps the raw body if it is not JSON. */
    private static String errorText(String body) {
        JsonArray errors = null;
        try {
            JsonElement json = JsonParser.parseString(body);
            if (json.isJsonObject()) {
                errors = json.getAsJsonObject().getAsJsonArray("errors");
            }
        } catch (JsonParseException e) {
            // Not JSON: keep the raw body.
        }
        if (errors == null) {
            return body.trim();
        }
        List<String> lines = new ArrayList<>();
        for (JsonElement error : errors) {
            // Vault's messages contain line breaks and tabs: keep them on one line.
            lines.add(error.getAsString().replaceAll("\\s+", " ").trim());
        }
        return String.join("; ", lines);
    }
}
