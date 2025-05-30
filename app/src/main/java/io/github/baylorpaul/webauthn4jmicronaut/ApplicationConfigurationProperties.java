package io.github.baylorpaul.webauthn4jmicronaut;

import io.micronaut.context.annotation.ConfigurationProperties;
import io.micronaut.context.annotation.Context;
import io.micronaut.core.annotation.NonNull;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
@ConfigurationProperties(ApplicationConfigurationProperties.PREFIX)
@Context // fail to start up the app if the properties in this configuration are not valid
public class ApplicationConfigurationProperties {
    public static final String PREFIX = "custom.application";

    /** the URL of the primary web page hosting content for the app, such as "http://localhost:5173" */
    private @NonNull @NotBlank String webAppUrl;
}
