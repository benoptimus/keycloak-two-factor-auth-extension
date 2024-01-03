package org.prg.twofactorauth.authenticators.directgrant;

import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.prg.twofactorauth.dto.SmsConstants;
import org.prg.twofactorauth.dto.TokenConstants;

public class SmsOtpVerificationAuthenticatorFactory implements AuthenticatorFactory{
    
	public static final String PROVIDER_ID = "sms-otp-authenticator";

	@Override
	public String getId() {
		return PROVIDER_ID;
	}

	@Override
	public String getDisplayType() {
		return "SMS OTP Verification";
	}

	@Override
	public String getHelpText() {
		return "Validates an OTP sent via SMS direct grant flow to the users mobile phone.";
	}

	@Override
	public String getReferenceCategory() {
		return TokenConstants.USR_CRED_SMS_CODE;
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return true;
	}

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return List.of(
			new ProviderConfigProperty(SmsConstants.CODE_LENGTH, "Code length", "The number of digits of the generated code.", ProviderConfigProperty.STRING_TYPE, 6),
			new ProviderConfigProperty(SmsConstants.CODE_TTL, "Time-to-live", "The time to live in seconds for the code to be valid.", ProviderConfigProperty.STRING_TYPE, "300"),
			new ProviderConfigProperty(SmsConstants.SENDER_ID, "SenderId", "The sender ID is displayed as the message sender on the receiving device.", ProviderConfigProperty.STRING_TYPE, "CAURIDOR"),
			new ProviderConfigProperty(SmsConstants.SIMULATION_MODE, "Simulation mode", "In simulation mode, the SMS won't be sent, but printed to the server logs", ProviderConfigProperty.BOOLEAN_TYPE, true),
			new ProviderConfigProperty(SmsConstants.PROVIDER_ID, "Provider id", "Id credential", ProviderConfigProperty.PASSWORD, "", true),
			new ProviderConfigProperty(SmsConstants.PROVIDER_KEY, "Provider key", "Key credential", ProviderConfigProperty.PASSWORD, "", true)
		);
	}

	@Override
	public Authenticator create(KeycloakSession session) {
        return new SmsOtpVerificationAuthenticator(session);
	}

	@Override
	public void init(Config.Scope config) {
	}

	@Override
	public void postInit(KeycloakSessionFactory factory) {
	}

	@Override
	public void close() {
	}
}
