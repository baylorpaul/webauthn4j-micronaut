package io.github.baylorpaul.webauthn4jmicronaut.dto.api.security.serialization;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * Some of the WebAuthn4J classes use @JsonValue on one of their fields to serialize the entire object with just that
 * single value. With Micronaut Serialization, this will cause a serialization issue if the object is null. This mixin
 * is to be applied to the wrapping object so that the null object is serialized as null. Otherwise, we may encounter an
 * error such as:
 * <code>NullPointerException: Cannot invoke "com.webauthn4j.data.AuthenticatorAttachment.getValue()" because "arg2" is null</code>.
 * The above can be resolved with:
 * <code>@SerdeImport(value = AuthenticatorSelectionCriteria.class, mixin = JsonIncludeAlwaysMixin.class)</code>.
 * Notice that is the wrapping class, not the null object.
 * The error described comes from the path in io.micronaut.serde.support.serializers.CustomizedObjectSerializer under
 * the `case NON_EMPTY` when the bean is null, which calls ErrorCatchingSerializer.isEmpty() ->
 * JsonValueSerializer.isEmpty(), which retrieves a null bean, which it is not expecting.
 */
@JsonInclude(JsonInclude.Include.ALWAYS)
public interface JsonIncludeAlwaysMixin {

}
