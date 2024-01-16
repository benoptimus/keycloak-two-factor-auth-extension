package org.prg.twofactorauth.authenticators.directgrant;

import java.util.List;
import java.util.stream.Collectors;

import javax.ws.rs.core.MultivaluedMap;
import javax.ws.rs.core.Response;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.events.Errors;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.prg.twofactorauth.credentials.BackupCodeCredentialModel;
import org.prg.twofactorauth.dto.EmailConstants;
import org.prg.twofactorauth.dto.TokenCodeConfig;
import org.prg.twofactorauth.dto.TokenConstants;
import org.prg.twofactorauth.utils.BaseDirectGrantAuthenticator;

import lombok.extern.jbosslog.JBossLog;


@JBossLog
public class BackupVerificationAuthenticator extends BaseDirectGrantAuthenticator{
    private final KeycloakSession session;

    private enum CODE_STATUS {
        VALID,
        INVALID
    }
    
    public BackupVerificationAuthenticator(KeycloakSession session) {
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
        user.addRequiredAction("VERIFICATION_EMAIL_CODE_GRANT_CONFIG");
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        if(!context.getUser().credentialManager().isConfiguredFor(OTPCredentialModel.TYPE)){
            context.success();
            return;
        }
        
        CODE_STATUS result = validateCode(context);
        if(result!=CODE_STATUS.VALID) {
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

        context.success();
    }

    protected CODE_STATUS validateCode(AuthenticationFlowContext context) {
        CODE_STATUS result = CODE_STATUS.INVALID;

        // note backup_code usage in event
        context.getEvent().detail("backup_code", "true");

        log.info("backup validateCode called ... ");
        MultivaluedMap<String, String> formData = context.getHttpRequest().getDecodedFormParameters();
        String enteredCode = formData.getFirst(TokenConstants.BACKUP_CODE);
       
        if (enteredCode == null) {
			return CODE_STATUS.INVALID;
		}

        UserModel user = context.getUser();
        
        UserCredentialModel backupCode = new UserCredentialModel(null, BackupCodeCredentialModel.TYPE, enteredCode, false);
        boolean backupCodeValid = user.credentialManager().isValid(backupCode);
        if (backupCodeValid) {
            result =  CODE_STATUS.VALID;
        }

        return result;
    }
}
