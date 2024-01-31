package io.angelinux.authdemoapp;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.util.List;

public class RobotAuthenticationProvider implements AuthenticationProvider {

    private final List<String> availablePasswords;

    public RobotAuthenticationProvider(List<String> availablePasswords) {
        this.availablePasswords = availablePasswords;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        RobotAuthentication authRequest = (RobotAuthentication) authentication; // we know is a RobotAuthentication
        String thePassword = authRequest.getPassword();
        if (!availablePasswords.contains(thePassword)) {
            throw new BadCredentialsException("You are not Ms Robot 🤖❌");
        }
        return RobotAuthentication.authenticated(); // 👍🏻 Successfully authentication request
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // RobotAuthentication class is the `same` or `is a superclass` or `superinterface` of the Class parameter?
        return RobotAuthentication.class.isAssignableFrom(authentication);
    }
}
