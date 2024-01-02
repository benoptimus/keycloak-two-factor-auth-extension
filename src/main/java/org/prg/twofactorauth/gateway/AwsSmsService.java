package org.prg.twofactorauth.gateway;

import java.util.HashMap;
import java.util.Map;

import org.prg.twofactorauth.dto.SmsConstants;

import lombok.extern.jbosslog.JBossLog;
import software.amazon.awssdk.auth.credentials.AwsCredentials;
import software.amazon.awssdk.auth.credentials.AwsCredentialsProvider;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.MessageAttributeValue;

@JBossLog
public class AwsSmsService implements SmsService{
    private static SnsClient sns;
	
	private final String senderId;
	private Map<String, String> config;

	AwsSmsService(Map<String, String> config) {
		this.config = config;
		senderId = config.get("senderId");
	}

	@Override
	public void send(String phoneNumber, String message) {
		if(sns==null){
			sns = SnsClient.builder()
						.credentialsProvider( new AwsCredentialsProvider() {

							@Override
							public AwsCredentials resolveCredentials() {
								return new AwsCredentials() {

									@Override
									public String accessKeyId() {
										return config.get(SmsConstants.PROVIDER_ID);
									}

									@Override
									public String secretAccessKey() {
										return config.get(SmsConstants.PROVIDER_KEY);
									}
									
								};
							}
							
						})
						.region(Region.US_EAST_1)
						.build();
		}
		log.info(config.get("senderId"));
		log.info(config.get(SmsConstants.PROVIDER_ID));
		log.info(config.get(SmsConstants.PROVIDER_KEY));
		log.info(sns);

		Map<String, MessageAttributeValue> messageAttributes = new HashMap<>();
		messageAttributes.put("AWS.SNS.SMS.SenderID",
			MessageAttributeValue.builder().stringValue(senderId).dataType("String").build());
		messageAttributes.put("AWS.SNS.SMS.SMSType",
			MessageAttributeValue.builder().stringValue("Transactional").dataType("String").build());

		sns.publish(builder -> builder
			.message(message)
			.phoneNumber(phoneNumber)
			.messageAttributes(messageAttributes));
	}
}
