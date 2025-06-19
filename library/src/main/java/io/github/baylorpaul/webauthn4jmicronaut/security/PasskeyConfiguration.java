package io.github.baylorpaul.webauthn4jmicronaut.security;

import io.micronaut.core.annotation.NonNull;
import jakarta.validation.constraints.NotBlank;

public interface PasskeyConfiguration {

    /** The Relying Party name, which is a human-readable title for your website, such as "My Passkey Example" */
    @NonNull @NotBlank String getRpName();
    /** The Relying Party ID, which is a unique identifier for your website, such as 'mywebsite.dev'. 'localhost' is okay for local dev */
    @NonNull @NotBlank String getRpId();
    /**
     * The URL at which registrations and authentications should occur.
     * 'http://localhost' and 'http://localhost:PORT' are also valid.
     * Do NOT include any trailing /
     */
    @NonNull @NotBlank String getOriginUrl();
}
