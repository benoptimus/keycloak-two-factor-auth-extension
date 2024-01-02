package org.prg.twofactorauth.gateway;

import java.util.Map;

import org.prg.twofactorauth.dto.SmsConstants;

import lombok.extern.jbosslog.JBossLog;

@JBossLog
public class SmsServiceFactory {
    public static SmsService get(Map<String, String> config) {
		if (Boolean.parseBoolean(config.getOrDefault(SmsConstants.SIMULATION_MODE, "false"))) {
			return (phoneNumber, message) ->
				log.warn(String.format("***** SIMULATION MODE ***** Would send SMS to %s with text: %s", phoneNumber, message));
		} else {
			return new AwsSmsService(config);
		}
	}
}
