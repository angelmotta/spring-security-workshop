package io.angelinux.authdemoapp;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.ArrayList;
import java.util.List;

public class RobotLoginConfigurer extends AbstractHttpConfigurer<RobotLoginConfigurer, HttpSecurity> {

    private final List<String> passwords = new ArrayList<>();

    @Override
    public void init(HttpSecurity http) throws Exception {
        // Step 1
        // Initialize a bunch of object
        // we put -> Authentication Providers
        http.authenticationProvider(new RobotAuthenticationProvider(passwords));
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        // Step 2
        // This also initialize objects, but can reuse objects from step 1, even from others configurers
        // Get the existing AuthenticationManager from the FilterChain
        AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class); // get the Object from Spring-Security-context
        // we put -> Filters
        http.addFilterBefore(new RobotFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class);
    }

    // Builder pattern to add passwords
    public RobotLoginConfigurer password(String password) {
        this.passwords.add(password);
        return this;
    }
}
