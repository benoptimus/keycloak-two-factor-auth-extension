package org.prg.twofactorauth.dto;

import org.keycloak.credential.hash.Pbkdf2Sha256PasswordHashProviderFactory;
import org.keycloak.models.RealmModel;

import lombok.Data;

@Data
public class TokenCodeConfig {

    private int backupCodeCount;
    private int backupCodeLength;

    private String hashingProviderId;
    private int backupCodeHashIterations;

    private static final TokenCodeConfig DEFAULT;

    static {

        TokenCodeConfig config = new TokenCodeConfig();
        config.setBackupCodeCount(Integer.getInteger("keycloak_backup_code_count", 10));
        config.setBackupCodeLength(Integer.getInteger("keycloak_backup_code_length", 8));
        config.setHashingProviderId(System.getProperty("keycloak_backup_code_hash_provider", Pbkdf2Sha256PasswordHashProviderFactory.ID));
        config.setBackupCodeHashIterations(Integer.getInteger("keycloak_backup_code_hash_iterations", 1000));

        DEFAULT = config;
    }

    public static TokenCodeConfig getConfig(RealmModel realmModel) {
        // TODO make backup-code handling configurable via realm
        return DEFAULT;
    }

}