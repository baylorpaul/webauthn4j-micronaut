package io.github.baylorpaul.webauthn4jmicronaut.security;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Context;
import io.micronaut.core.annotation.NonNull;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@ConfigurationProperties(PasskeyConfigurationProperties.PREFIX)
@Context // fail to start up the app if the properties in this configuration are not valid
public class PasskeyConfigurationProperties {
    public static final String PREFIX = "passkey.configuration";

    /** The Relying Party name, which is a human-readable title for your website, such as "My Passkey Example" */
    private @NonNull @NotBlank String rpName;
    /** The Relying Party ID, which is a unique identifier for your website, such as 'mywebsite.dev'. 'localhost' is okay for local dev */
    private @NonNull @NotBlank String rpId;
    /**
     * The URL at which registrations and authentications should occur.
     * 'http://localhost' and 'http://localhost:PORT' are also valid.
     * Do NOT include any trailing /
     */
    private @NonNull @NotBlank String originUrl;
}
