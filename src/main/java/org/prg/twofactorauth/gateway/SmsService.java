package org.prg.twofactorauth.gateway;

public interface SmsService {
    void send(String phoneNumber, String message);
} 