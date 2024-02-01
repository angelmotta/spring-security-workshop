package io.angelinux.authdemoapp;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class RateLimitedAuthenticationProvider implements AuthenticationProvider {
    // this it's going to wrap the OidcAuthorizationCodeAuthenticationProvider given by Spring Security
    private final AuthenticationProvider delegate;
    private final Map<String, Instant> cache = new ConcurrentHashMap<String, Instant>();
    private final Integer waitingTimeInMinutes = 1;
    public RateLimitedAuthenticationProvider(AuthenticationProvider delegate) {
        this.delegate = delegate;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        var parentAuthentication = delegate.authenticate(authentication); // this could be null
        if (parentAuthentication == null) {
            return null; // Try with another AuthenticationProvider
        }
        if (!isAllowedUpdateCache(parentAuthentication)) {
            // You have to wait a little more 👎🏻
            throw new BadCredentialsException("🤠Not so fast bro!");
        }

        return parentAuthentication;
    }

    private boolean isAllowedUpdateCache(Authentication parentAuthentication) {
        var lastLoginInstant = cache.get(parentAuthentication.getName());
        var currentInstant = Instant.now();
        cache.put(parentAuthentication.getName(), currentInstant);
        return lastLoginInstant == null ||
                lastLoginInstant.plus(Duration.ofMinutes(waitingTimeInMinutes)).isBefore(currentInstant);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        // In this case OidcAuthorizationCodeAuthenticationProvider support Oauth2LoginAuthenticationToken
        return delegate.supports(authentication); // It will support the same as the delegate
    }
}
