package io.github.baylorpaul.webauthn4jmicronaut.service.model;

import io.micronaut.core.annotation.ReflectionConfig;
import io.micronaut.core.annotation.TypeHint;
import io.micronaut.email.Contact;

/**
 * Native Image supports reflection but needs to know ahead-of-time the reflectively accessed program elements.
 * Grant access to model data for native image builds on classes where we cannot add @ReflectiveAccess directly.
 * Without this, the reflectively accessed model data is inaccessible for native images.
 * These reflection hints will generate a "reflect-config.json" to use when building the native image.
 * @see <a href="https://guides.micronaut.io/latest/micronaut-graalvm-reflection-gradle-java.html">Generate Reflection Metadata for GraalVM Native Image</a>
 */
@ReflectionConfig(type = Contact.class, accessType = {TypeHint.AccessType.ALL_PUBLIC_METHODS})
public class GraalConfig {
}
