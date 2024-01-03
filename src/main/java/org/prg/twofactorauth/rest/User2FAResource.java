package org.prg.twofactorauth.rest;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.keycloak.authentication.AuthenticationFlow;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.ConfigurableAuthenticatorFactory;
import org.keycloak.common.util.SecretGenerator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.credential.CredentialProvider;
import org.keycloak.credential.hash.PasswordHashProvider;
import org.keycloak.email.EmailException;
import org.keycloak.email.EmailTemplateProvider;
import org.keycloak.events.Errors;
import org.prg.twofactorauth.authenticators.browser.EmailOtpFormAuthenticator;
import org.prg.twofactorauth.authenticators.browser.SmsOtpFormAuthenticatorFactory;
import org.prg.twofactorauth.authenticators.directgrant.EmailOtpVerificationAuthenticator;
import org.prg.twofactorauth.authenticators.directgrant.EmailOtpVerificationAuthenticatorFactory;
import org.prg.twofactorauth.dto.BackupCodeConfig;
import org.prg.twofactorauth.dto.EmailConstants;
import org.prg.twofactorauth.dto.SmsConstants;
import org.prg.twofactorauth.dto.TokenCodeConfig;
import org.prg.twofactorauth.dto.TokenConstants;
import org.prg.twofactorauth.dto.TwoFactorAuthAuthenticationCode;
import org.prg.twofactorauth.dto.TwoFactorAuthSecretData;
import org.prg.twofactorauth.dto.TwoFactorAuthSubmission;
import org.prg.twofactorauth.dto.TwoFactorAuthVerificationData;
import org.prg.twofactorauth.gateway.SmsServiceFactory;

import lombok.extern.jbosslog.JBossLog;

import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.UserProvider;
import org.keycloak.models.credential.OTPCredentialModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.models.utils.Base32;
import org.keycloak.models.utils.HmacOTP;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.services.resources.admin.AuthenticationManagementResource;
import org.keycloak.theme.Theme;
import org.keycloak.utils.CredentialHelper;
import org.keycloak.utils.TotpUtils;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;

@JBossLog
public class User2FAResource {

    private enum TYPE_CODE {
        SMS,
        EMAIL
    }

	private final KeycloakSession session;
    private final UserModel user;

    public final int TotpSecretLength = 20;
	
	public User2FAResource(KeycloakSession session, UserModel user) {
		this.session = session;
        this.user = user;
	}

    @GET
    @Path("generate-2fa")
    @NoCache
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response generate2FA() {
        final RealmModel realm = this.session.getContext().getRealm();
        final String totpSecret = HmacOTP.generateSecret(TotpSecretLength);
        final String totpSecretQrCode = TotpUtils.qrCode(totpSecret, realm, user);
        final String totpSecretEncoded = Base32.encode(totpSecret.getBytes());
        return Response.ok(new TwoFactorAuthSecretData(totpSecretEncoded, totpSecretQrCode)).build();
    }

    @POST
    @NoCache
    @Path("validate-2fa-code")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response validate2FACode(final TwoFactorAuthVerificationData submission) {
        if (!submission.isValid()) {
            throw new BadRequestException("one or more data field for otp validation are blank");
        }

        final RealmModel realm = this.session.getContext().getRealm();
        final CredentialModel credentialModel = user.credentialManager().getStoredCredentialByNameAndType(submission.getDeviceName(), OTPCredentialModel.TYPE);
        if (credentialModel == null) {
            throw new BadRequestException("device not found");
        }
        boolean isCredentialsValid;
        try {
            var otpCredentialProvider = session.getProvider(CredentialProvider.class, "keycloak-otp");
            final OTPCredentialModel otpCredentialModel = OTPCredentialModel.createFromCredentialModel(credentialModel);
            final String credentialId = otpCredentialModel.getId();
            isCredentialsValid = user.credentialManager().isValid(new UserCredentialModel(credentialId, otpCredentialProvider.getType(), submission.getTotpCode()));
        } catch (RuntimeException e) {
            e.printStackTrace();
            throw new InternalServerErrorException("internal error");
        }

        if (!isCredentialsValid) {
            throw new BadRequestException("invalid totp code");
        }

        return Response.noContent().build();
    }

    @POST
    @NoCache
    @Path("submit-2fa")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response register2FA(final TwoFactorAuthSubmission submission) {
        if (!submission.isValid()) {
            throw new BadRequestException("one or more data field for otp registration are blank");
        }

        final String encodedTotpSecret = submission.getEncodedTotpSecret();
        final String totpSecret = new String(Base32.decode(encodedTotpSecret));
        if (totpSecret.length() < TotpSecretLength) {
            throw new BadRequestException("totp secret is invalid");
        }

        final RealmModel realm = this.session.getContext().getRealm();
        final CredentialModel credentialModel = user.credentialManager().getStoredCredentialByNameAndType(submission.getDeviceName(), OTPCredentialModel.TYPE);
        if (credentialModel != null && !submission.isOverwrite()) {
            throw new ForbiddenException("2FA is already configured for device: " + submission.getDeviceName());
        }

        final OTPCredentialModel otpCredentialModel = OTPCredentialModel.createFromPolicy(realm, totpSecret, submission.getDeviceName());
        if (!CredentialHelper.createOTPCredential(this.session, realm, user, submission.getTotpInitialCode(), otpCredentialModel)) {
            throw new BadRequestException("otp registration data is invalid");
        }

        return Response.noContent().build();
    }

    @POST
    @NoCache
    @Path("email-authentication-code")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response emailCodeAuthentication(final TwoFactorAuthAuthenticationCode authencationData) {
        if (!authencationData.isValid()) {
            throw new BadRequestException("one or more data field for authentication code are blank");
        }

        RealmModel realm = session.getContext().getRealm();
        UserProvider userProvider = session.getProvider(UserProvider.class);
        UserModel user_to_notify = userProvider.getUserByUsername(realm, authencationData.getUsername());

        if(user_to_notify==null){
            user_to_notify = userProvider.getUserByEmail(realm, authencationData.getUsername());
        }

        if(user_to_notify==null){
            throw new ForbiddenException(Errors.INVALID_USER_CREDENTIALS);
        }

        if(!user_to_notify.isEnabled()){
            throw new ForbiddenException("Your Account is disabled");
        }

        if(!user_to_notify.isEmailVerified()){
            throw new ForbiddenException("Your email is not verified");
        }
    
        if(!user_to_notify.getEmail().equals(user.getEmail())){
            throw new ForbiddenException(Errors.INVALID_USER_CREDENTIALS);
        }

        UserCredentialModel password = new UserCredentialModel(null, PasswordCredentialModel.TYPE, authencationData.getPassword(), false);
        if(!user_to_notify.credentialManager().isValid(password)){
            throw new ForbiddenException(Errors.INVALID_USER_CREDENTIALS);
        }

        generateAndSendEmailCode();

        return Response.noContent().build();
    }

    @POST
    @NoCache
    @Path("sms-authentication-code")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response smsCodeAuthentication(final TwoFactorAuthAuthenticationCode authencationData) {
        if (!authencationData.isValid()) {
            throw new BadRequestException("one or more data field for authentication code are blank");
        }

        RealmModel realm = session.getContext().getRealm();
        UserProvider userProvider = session.getProvider(UserProvider.class);
        UserModel user_to_notify = userProvider.getUserByUsername(realm, authencationData.getUsername());

        if(user_to_notify==null){
            user_to_notify = userProvider.getUserByEmail(realm, authencationData.getUsername());
        }

        if(user_to_notify==null){
            throw new ForbiddenException(Errors.INVALID_USER_CREDENTIALS);
        }

        if(!user_to_notify.isEnabled()){
            throw new ForbiddenException("Your Account is disabled");
        }

       //check if phone is verified
        String mobileNumber = user.getFirstAttribute(SmsConstants.MOBILE_NUMBER_FIELD);
         String mobileNumber1 = user_to_notify.getFirstAttribute(SmsConstants.MOBILE_NUMBER_FIELD);
        if(!mobileNumber.equals(mobileNumber1)){
            throw new ForbiddenException(Errors.INVALID_USER_CREDENTIALS);
        }

        UserCredentialModel password = new UserCredentialModel(null, PasswordCredentialModel.TYPE, authencationData.getPassword(), false);
        if(!user_to_notify.credentialManager().isValid(password)){
            throw new ForbiddenException(Errors.INVALID_USER_CREDENTIALS);
        }

        generateAndSendSmsCode();

        return Response.noContent().build();
    }

    //https://github.com/nickpack/keycloak-sms-authenticator-sns/blob/develop/src/main/java/six/six/keycloak/authenticator/KeycloakSmsAuthenticator.java
    // Store the code + expiration time in a UserCredential. Keycloak will persist these in the DB.
    // When the code is validated on another node (in a clustered environment) the other nodes have access to it's values too.
    private String generateCode(TYPE_CODE typeCode) {
        int length = 6;
        int ttl = 300;
        String credentialName = TokenConstants.USR_CRED_EMAIL_CODE;
        String actionName = "Email";

        if(typeCode==TYPE_CODE.SMS){
            credentialName = TokenConstants.USR_CRED_SMS_CODE;
            actionName="Sms";
        }
         
       
    
        String code = SecretGenerator.getInstance().randomString(length, SecretGenerator.DIGITS);

        //delete expired email code
        List<CredentialModel>  credentials = user.credentialManager()
                                                .getStoredCredentialsByTypeStream(credentialName)
                                                .collect(Collectors.toList());
        for (CredentialModel item : credentials) {
            if(item.getCreatedDate()+ (ttl * 1000L)<=System.currentTimeMillis()){
                user.credentialManager().removeStoredCredentialById(item.getId());
            }
            else{
                if(typeCode==TYPE_CODE.SMS){
                 user.credentialManager().removeStoredCredentialById(item.getId());
                }
            }
        }

        TokenCodeConfig tokenCodeConfig = TokenCodeConfig.getConfig(session.getContext().getRealm());

        PasswordHashProvider passwordHashProvider = session.getProvider(PasswordHashProvider.class,
                    tokenCodeConfig.getHashingProviderId());
                if (passwordHashProvider == null) {
                    log.errorf("Could not find hashProvider to hash backup codes. realm=%s user=%s providerId=%s",
                            session.getContext().getRealm().getId(), user.getId(), tokenCodeConfig.getHashingProviderId());
                    throw new RuntimeException("Cloud not find hashProvider to hash backup codes");
                }

        Long time = System.currentTimeMillis();
        CredentialModel credential = new CredentialModel();
        PasswordCredentialModel encodedBackupCode = passwordHashProvider.encodedCredential(code, tokenCodeConfig.getBackupCodeHashIterations());
        credential.setType(credentialName);
        credential.setCreatedDate(time);

        SimpleDateFormat sdf = new SimpleDateFormat("MMM dd,yyyy HH:mm"); 
        Date resultdate = new Date(time);
        credential.setUserLabel(actionName+" authentication code generated at  "+sdf.format(resultdate));
        credential.setSecretData(encodedBackupCode.getSecretData());
        credential.setCredentialData(encodedBackupCode.getCredentialData());
        user.credentialManager().createStoredCredential(credential);
        return code;
    }

    private void generateAndSendEmailCode(){
        RealmModel realm = session.getContext().getRealm();
        int ttl = EmailConstants.DEFAULT_TTL;
        String code = generateCode(TYPE_CODE.EMAIL);
        
        log.info("Send authentication code via email to user : "+user.getEmail());
        if (user.getEmail() == null) {
            log.warnf("Could not send access code email due to missing email. realm=%s user=%s", realm.getId(), user.getUsername());
            throw new BadRequestException(Errors.INVALID_CONFIG);
        }

        Map<String, Object> mailBodyAttributes = new HashMap<>();
        mailBodyAttributes.put("username", user.getUsername());
        mailBodyAttributes.put("code", code);
        mailBodyAttributes.put("ttl", ttl);

        String realmName = realm.getDisplayName() != null ? realm.getDisplayName() : realm.getName();
        List<Object> subjectParams = List.of(realmName);
        try {
            EmailTemplateProvider emailProvider = session.getProvider(EmailTemplateProvider.class);
            emailProvider.setRealm(realm);
            emailProvider.setUser(user);
            // Don't forget to add the welcome-email.ftl (html and text) template to your theme.
            emailProvider.send("emailCodeSubject", subjectParams, "code-email.ftl", mailBodyAttributes);
        } catch (EmailException eex) {
            log.errorf(eex, "Failed to send access code email. realm=%s user=%s", realm.getId(), user.getUsername());
        }
    }

    private void generateAndSendSmsCode(){
        RealmModel realm = session.getContext().getRealm();
        int ttl = EmailConstants.DEFAULT_TTL;
        String code = generateCode(TYPE_CODE.SMS);
        
        String mobileNumber = user.getFirstAttribute(SmsConstants.MOBILE_NUMBER_FIELD);
        
        log.info("Send authentication code via sms to user : "+user.getEmail());
        if (mobileNumber == null || mobileNumber.isEmpty() || mobileNumber.isBlank()) {
            log.warnf("Could not send access code sms due to missing phone number. realm=%s user=%s", realm.getId(), user.getUsername());
            throw new BadRequestException(Errors.INVALID_CONFIG);
        }

       try {
        
            AuthenticatorConfigModel config = getConfigAuthenticator(SmsConstants.ALIAS_DIRECT_GRANT);
            log.info(config.getConfig().get(SmsConstants.CODE_LENGTH));
            
			Theme theme = session.theme().getTheme(Theme.Type.LOGIN);
			Locale locale = session.getContext().resolveLocale(user);
			String smsAuthText = theme.getMessages(locale).getProperty("smsAuthText");
			log.info(smsAuthText);
			String smsText = String.format(smsAuthText, code, Math.floorDiv(ttl, 60));

			SmsServiceFactory.get(config.getConfig()).send(mobileNumber, smsText);
		} catch (Exception e) {
			log.error(e.getMessage());
		}
    }


    private AuthenticatorConfigModel getConfigAuthenticator(String authenticatorAliasName){
        return session.getContext().getRealm().getAuthenticatorConfigByAlias(authenticatorAliasName);
    }
}