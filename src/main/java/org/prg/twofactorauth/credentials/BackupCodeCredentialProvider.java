package org.prg.twofactorauth.credentials;

import java.util.List;
import java.util.stream.Collectors;

import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.CredentialTypeMetadata;
import org.keycloak.credential.CredentialTypeMetadataContext;
import org.keycloak.credential.CredentialTypeMetadata.CredentialTypeMetadataBuilder;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.prg.twofactorauth.action.GenerateBackupCodeAction;
import org.prg.twofactorauth.dto.BackupCode;
import org.prg.twofactorauth.dto.BackupCodeConfig;

import lombok.extern.jbosslog.JBossLog;

@JBossLog
public class BackupCodeCredentialProvider implements CredentialProvider<CredentialModel>, CredentialInputValidator {

    private final KeycloakSession session;

    public BackupCodeCredentialProvider(KeycloakSession session) {
        this.session = session;
    }

    public BackupCodeCredentialProvider getCredentialProvider(KeycloakSession session) {
        return (BackupCodeCredentialProvider)session.getProvider(CredentialProvider.class, BackupCodeCredentialProviderFactory.ID);
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        return getType().equals(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        SubjectCredentialManager userCredentialManager = user.credentialManager();
        return userCredentialManager.getStoredCredentialsByTypeStream(credentialType).findAny().isPresent();
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {

        String codeInput = credentialInput.getChallengeResponse();
        BackupCodeConfig backupCodeConfig = getBackupCodeConfig(realm);
        PasswordHashProvider passwordHashProvider = session.getProvider(PasswordHashProvider.class,
                backupCodeConfig.getHashingProviderId());

        SubjectCredentialManager ucm = user.credentialManager();
        List<CredentialModel> backupCodes = ucm.getStoredCredentialsByTypeStream(getType())
                .collect(Collectors.toList());

        for (CredentialModel backupCode : backupCodes) {
            // check if the given backup code matches
            if (passwordHashProvider.verify(codeInput, PasswordCredentialModel.createFromCredentialModel(backupCode))) {
                // we found matching backup code
                handleUsedBackupCode(realm, user, ucm, backupCode);
                return true;
            }
        }

        // no matching backup code found
        return false;
    }

    protected void handleUsedBackupCode(RealmModel realm, UserModel user, SubjectCredentialManager ucm, CredentialModel backupCode) {
        // delete backup code entry
        ucm.removeStoredCredentialById(backupCode.getId());
    }

    @Override
    public String getType() {
        return BackupCodeCredentialModel.TYPE;
    }

    @Override
    public CredentialModel createCredential(RealmModel realm, UserModel user, CredentialModel credentialModelInput) {

        if (!(credentialModelInput instanceof BackupCodeCredentialModel)) {
            return null;
        }

        BackupCodeConfig backupCodeConfig = getBackupCodeConfig(realm);

        BackupCodeCredentialModel backupCodeCredentialModel = (BackupCodeCredentialModel) credentialModelInput;
        BackupCode backupCode = backupCodeCredentialModel.getBackupCode();

        PasswordHashProvider passwordHashProvider = session.getProvider(PasswordHashProvider.class,
                backupCodeConfig.getHashingProviderId());
        if (passwordHashProvider == null) {
            log.errorf("Could not find hashProvider to hash backup codes. realm=%s user=%s providerId=%s",
                    realm.getId(), user.getId(), backupCodeConfig.getHashingProviderId());
            throw new RuntimeException("Cloud not find hashProvider to hash backup codes");
        }

        PasswordCredentialModel encodedBackupCode = encodeBackupCode(backupCode, backupCodeConfig, passwordHashProvider);
        CredentialModel backupCodeModel = createBackupCodeCredentialModel(backupCode, encodedBackupCode);

        user.credentialManager().createStoredCredential(backupCodeModel);
        log.debug(backupCodeModel.getCredentialData());
        return backupCodeModel;
    }

    protected CredentialModel createBackupCodeCredentialModel(BackupCode backupCode, PasswordCredentialModel encodedBackupCode) {

        CredentialModel model = new CredentialModel();
        model.setType(getType());
        model.setCreatedDate(backupCode.getCreatedAt());
        // TODO make userlabel configurable
        model.setUserLabel(createBackupCodeUserLabel(backupCode));
        model.setSecretData(encodedBackupCode.getSecretData());
        model.setCredentialData(encodedBackupCode.getCredentialData());
        return model;
    }

    protected PasswordCredentialModel encodeBackupCode(
            BackupCode backupCode, BackupCodeConfig backupCodeConfig, PasswordHashProvider passwordHashProvider) {
        return passwordHashProvider.encodedCredential(backupCode.getCode(), backupCodeConfig.getBackupCodeHashIterations());
    }

    protected String createBackupCodeUserLabel(BackupCode backupCode) {
        return "Backup-Code: " + backupCode.getId();
    }

    protected BackupCodeConfig getBackupCodeConfig(RealmModel realm) {
        return BackupCodeConfig.getConfig(realm);
    }

    @Override
    public boolean deleteCredential(RealmModel realm, UserModel user, String credentialId) {
        SubjectCredentialManager userCredentialManager = user.credentialManager();
        return userCredentialManager.removeStoredCredentialById(credentialId);
    }

    @Override
    public CredentialModel getCredentialFromModel(CredentialModel model) {

        if (!getType().equals(model.getType())) {
            return null;
        }

        return model;
    }

    @Override
    public CredentialTypeMetadata getCredentialTypeMetadata(CredentialTypeMetadataContext metadataContext) {

        CredentialTypeMetadataBuilder builder = CredentialTypeMetadata.builder();
        builder.type(getType());
        builder.category(CredentialTypeMetadata.Category.TWO_FACTOR);
        builder.createAction(GenerateBackupCodeAction.ID);
        // TODO make backup code removal configurable
        builder.removeable(false);
        builder.displayName("backup-codes-display-name");
        builder.helpText("backup-codes-help-text");
        // builder.updateAction(GenerateBackupCodeAction.ID);
        // TODO configure proper FA icon for backup codes
        builder.iconCssClass("kcAuthenticatorBackupCodeClass");

        return builder.build(session);
    }
}
