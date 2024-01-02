package org.prg.twofactorauth.dto;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class TwoFactorAuthAuthenticationCode {
    private final String username;
    private final String password;
    
    @JsonCreator
    public TwoFactorAuthAuthenticationCode(@JsonProperty(value = "username") String username,@JsonProperty(value = "password") String password) {
        this.username = username;
        this.password = password;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }

    

    public boolean isValid() {
        return username != null &&
                password != null &&
                !username.isBlank() &&
                !password.isBlank();
    }
}