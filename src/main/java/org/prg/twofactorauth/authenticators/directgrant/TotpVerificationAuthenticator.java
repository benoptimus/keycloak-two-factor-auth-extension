package org.prg.twofactorauth.authenticators.directgrant;

import javax.persistence.EntityManager;
import javax.ws.rs.core.Response;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.events.Errors;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.prg.twofactorauth.utils.BaseDirectGrantAuthenticator;

import lombok.extern.jbosslog.JBossLog;

@JBossLog
public class TotpVerificationAuthenticator extends BaseDirectGrantAuthenticator{
    private final KeycloakSession session;

    public TotpVerificationAuthenticator(KeycloakSession session) {
        this.session = session;
        if (getRealm() == null) {
            throw new IllegalStateException("The service cannot accept a session without a realm in its context.");
        }
    }

    protected RealmModel getRealm() {
        return session.getContext().getRealm();
    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
        user.addRequiredAction("VERIFICATION_OTP_GRANT_CONFIG");
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        String code = context.getHttpRequest().getDecodedFormParameters().getFirst("totp");
        
        if(code==null && context.getExecution().isAlternative()){
                context.attempted();
                return;
            }

        if(!context.getUser().credentialManager().isConfiguredFor(OTPCredentialModel.TYPE)){
            context.success();
            return;
        }

        UserModel user = context.getUser();
        //test all device name later
        final CredentialModel credentialModel = user.credentialManager().getStoredCredentialByNameAndType("mpp-device", OTPCredentialModel.TYPE);
        if(credentialModel == null) {
            context.getEvent().user(context.getUser());
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);
            
            if(context.getExecution().isAlternative()){
                context.attempted();
                return;
            }

            Response challenge = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials");
            context.failure(AuthenticationFlowError.INVALID_USER, challenge);
            return;
        }

        boolean isCredentialsValid;
        try {
            var otpCredentialProvider = session.getProvider(CredentialProvider.class, "keycloak-otp");
            final OTPCredentialModel otpCredentialModel = OTPCredentialModel.createFromCredentialModel(credentialModel);
            final String credentialId = otpCredentialModel.getId();
            isCredentialsValid = user.credentialManager().isValid(new UserCredentialModel(credentialId, otpCredentialProvider.getType(), code));
        } catch (RuntimeException e) {
            if(context.getExecution().isAlternative()){
                context.attempted();
                return;
            }
            e.printStackTrace();
            context.getEvent().user(context.getUser());
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);

            Response challenge = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials");
            context.failure(AuthenticationFlowError.INVALID_USER, challenge);
            return;
        }

        if (!isCredentialsValid) {
            if(context.getExecution().isAlternative()){
                context.attempted();
                return;
            }
            context.getEvent().user(context.getUser());
            context.getEvent().error(Errors.INVALID_USER_CREDENTIALS);

            Response challenge = errorResponse(Response.Status.UNAUTHORIZED.getStatusCode(), "invalid_grant", "Invalid user credentials");
            context.failure(AuthenticationFlowError.INVALID_USER, challenge);
            return;
        }
        context.success();
    }
}
