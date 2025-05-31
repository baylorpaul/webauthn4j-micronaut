package io.github.baylorpaul.webauthn4jmicronaut;

import com.webauthn4j.data.*;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.*;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.COSEKeyType;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.CredentialPropertiesOutput;
import io.micronaut.core.annotation.ReflectionConfig;
import io.micronaut.core.annotation.TypeHint;

/**
 * Native Image supports reflection but needs to know ahead-of-time the reflectively accessed program elements.
 * Grant access to model data for native image builds on classes where we cannot add @ReflectiveAccess directly.
 * Without this, the reflectively accessed model data is inaccessible for native images.
 * These reflection hints will generate a "reflect-config.json" to use when building the native image.
 * To map values correctly, native builds require @ReflectiveAccess (or @ReflectionConfig if it's a library that can't
 * be changed). Without this, we may get an exception in native builds, such as:
 * <code>Native CBOR deserialization issue: Could not resolve type id 'EC2' as a subtype of `com.webauthn4j.data.attestation.authenticator.COSEKey`: known type ids = [1, 2, 3]</code>
 * @see <a href="https://github.com/micronaut-projects/micronaut-core/issues/6672">Regarding @JsonSubTypes, such as in COSEKey.java</a>
 * @see <a href="https://guides.micronaut.io/latest/micronaut-graalvm-reflection-gradle-java.html">Generate Reflection Metadata for GraalVM Native Image</a>
 */
@ReflectionConfig(type = PublicKeyCredential.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = AuthenticatorAttestationResponse.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = AuthenticatorTransport.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = AuthenticationExtensionsAuthenticatorOutputs.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = AuthenticationExtensionsClientOutputs.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = AuthenticatorAttachment.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = AuthenticatorAssertionResponse.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = AttestationObject.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = COSEAlgorithmIdentifier.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = CollectedClientData.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = ClientDataType.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = CredentialPropertiesOutput.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = com.webauthn4j.converter.jackson.deserializer.cbor.CredentialProtectionPolicyDeserializer.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = com.webauthn4j.converter.jackson.deserializer.json.CredentialProtectionPolicyDeserializer.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = com.webauthn4j.converter.jackson.serializer.cbor.CredentialProtectionPolicySerializer.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = com.webauthn4j.converter.jackson.serializer.json.CredentialProtectionPolicySerializer.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = Origin.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
// TODO include other attestation statements, etc. Include any other WebAuthn4J classes that might be encountered
@ReflectionConfig(type = NoneAttestationStatement.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = COSEKey.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
//@ReflectionConfig(type = AbstractCOSEKey.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = EdDSACOSEKey.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = EC2COSEKey.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = RSACOSEKey.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = Curve.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
@ReflectionConfig(type = COSEKeyType.class, accessType = {TypeHint.AccessType.ALL_PUBLIC, TypeHint.AccessType.ALL_DECLARED_CONSTRUCTORS, TypeHint.AccessType.ALL_DECLARED_METHODS, TypeHint.AccessType.ALL_DECLARED_FIELDS})
public class WebAuthn4jReflectionConfig {
}
