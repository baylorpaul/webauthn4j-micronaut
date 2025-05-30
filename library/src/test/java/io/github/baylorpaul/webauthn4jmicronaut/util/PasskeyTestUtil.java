package io.github.baylorpaul.webauthn4jmicronaut.util;

import com.webauthn4j.credential.CredentialRecord;
import com.webauthn4j.credential.CredentialRecordImpl;
import com.webauthn4j.data.AuthenticatorTransport;
import com.webauthn4j.data.attestation.authenticator.*;
import com.webauthn4j.data.attestation.statement.AttestationStatement;
import com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier;
import com.webauthn4j.data.attestation.statement.NoneAttestationStatement;
import com.webauthn4j.data.client.ClientDataType;
import com.webauthn4j.data.client.CollectedClientData;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.extension.authenticator.AuthenticationExtensionsAuthenticatorOutputs;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientOutputs;
import com.webauthn4j.data.extension.client.RegistrationExtensionClientOutput;
import io.micronaut.core.annotation.NonNull;

import java.util.Set;

public class PasskeyTestUtil {

	public static CredentialRecord buildFakeCredentialRecord(
			@NonNull String originUrl, @NonNull Challenge savedChallenge
	) {
		AttestationStatement attestationStatement = new NoneAttestationStatement();
		Boolean uvInitialized = true;
		Boolean backupEligible = true;
		Boolean backupState = true;
		long counter = 0L;

		AttestedCredentialData attestedCredentialData = buildFakeAttestedCredentialData();

		AuthenticationExtensionsAuthenticatorOutputs<RegistrationExtensionAuthenticatorOutput> authenticatorExtensions = new AuthenticationExtensionsAuthenticatorOutputs.BuilderForRegistration()
				.build();
		Origin origin = new Origin(originUrl);
		CollectedClientData clientData = new CollectedClientData(
				ClientDataType.WEBAUTHN_CREATE,
				savedChallenge,
				origin,
				null,
				null
		);
		AuthenticationExtensionsClientOutputs<RegistrationExtensionClientOutput> clientExtensions = new AuthenticationExtensionsClientOutputs.BuilderForRegistration()
				.build();
		Set<AuthenticatorTransport> transports = Set.of(AuthenticatorTransport.INTERNAL, AuthenticatorTransport.HYBRID);

		return new CredentialRecordImpl(
				attestationStatement,
				uvInitialized,
				backupEligible,
				backupState,
				counter,
				attestedCredentialData,
				authenticatorExtensions,
				clientData,
				clientExtensions,
				transports
		);
	}

	public static AttestedCredentialData buildFakeAttestedCredentialData() {
		AAGUID aaguid = new AAGUID("fbfc3007-154e-4ecc-8c0b-6e020557d7bd");
		byte[] attestedCredentialId = new byte[]{4,26,-10,17,111,56,79,-18,-33,77,-21,-50,-104,51,121,57,16,9,-58,91};
		COSEKey coseKey = new EC2COSEKey(
				null,
				COSEAlgorithmIdentifier.ES256,
				null,
				Curve.SECP256R1,
				new byte[]{-40,88,-22,123,-122,110,79,47,-32,-77,92,-21,101,-84,73,-118,-19,-90,-12,-80,52,-31,-57,5,32,67,-36,-2,92,85,2,6},
				new byte[]{-30,75,-86,-28,-68,118,-45,-36,-46,49,-108,46,-9,114,110,31,-68,-44,95,127,-73,110,-23,-2,-64,-10,16,83,28,-102,53,82}
		);

		return new AttestedCredentialData(aaguid, attestedCredentialId, coseKey);
	}
}
