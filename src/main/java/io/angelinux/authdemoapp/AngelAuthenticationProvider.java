package io.angelinux.authdemoapp;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;

/*/
Custom Authentication Provider for user `angel` which doesn't remember his credential
 */
public class AngelAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        if (!"angel".equals(username)) { // should we handle this request?
            return null;    // another AuthenticationProvider should be tried.
        }
        // This user is `angel` 😇
        return UsernamePasswordAuthenticationToken.authenticated(
                "angel",
                null,
                AuthorityUtils.createAuthorityList("ROLE_admin")
        );
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
