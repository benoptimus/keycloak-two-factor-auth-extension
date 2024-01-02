package org.prg.twofactorauth.dto;

public class TokenConstants {
    //https://github.com/nickpack/keycloak-sms-authenticator-sns/blob/develop/src/main/java/six/six/keycloak/KeycloakSmsConstants.java#L6
    // User credentials (used to persist the sent email code + expiration time cluster wide)
    public static final String USR_CRED_EMAIL_CODE = "email-auth-code";
    public static final String USR_CRED_SMS_CODE = "sms-auth-code";
    public static final String EMAIL_CODE = "emailCode";
    public static final String SMS_CODE = "smsCode";

}

