package com.groupdocs.samples.vault;

import java.io.IOException;

/**
 * A Vault request failed; the message carries Vault's own error text.
 */
public final class VaultException extends IOException {
    private final int status;

    public VaultException(String message, int status) {
        super(message);
        this.status = status;
    }

    /** HTTP status of the failed request, or 0 if Vault could not be reached. */
    public int getStatus() {
        return status;
    }
}
