package io.angelinux.authdemoapp;

import jakarta.servlet.http.HttpServletRequest;
import org.ietf.jgss.Oid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Optional;

@RestController
public class WebController {

//    private final JwtDecoderFactory idTokenDecoderFactory;

//    public WebController(JwtDecoderFactory idTokenDecoderFactory) {
//        this.idTokenDecoderFactory = idTokenDecoderFactory;
//    }

    @GetMapping("/")
    public String publicPage() {
        return "Hello world!";
    }

    @GetMapping("/private")
    public String privatePage(Authentication authentication) {
        //return "Welcome to the VIP Room [ " + authentication.getName() + " ] 😃☕️🎉";
        return "Welcome to the VIP Room [ " + getName(authentication) + " ] 😃☕️🎉";
    }

    @PostMapping("/signup")
    public String signupFlow(Authentication authentication) {
        System.out.println("---- Controller: Id token validation done ----");
        System.out.println(authentication);
        String user = getName(authentication);
        authentication.getPrincipal();
        System.out.println("user:");
        System.out.println(user);
        if (authentication != null && authentication instanceof JwtAuthenticationToken) {
            System.out.println("this is jwtAuthentication");
            var authToken = (JwtAuthenticationToken) authentication;
            var principal = authToken.getPrincipal();
            if (principal instanceof Jwt) {
                Jwt jwtToken = (Jwt) principal;
                var myClaim = jwtToken.getClaims();
                System.out.println("-- print claims --");
                System.out.println(myClaim);
                System.out.println(myClaim.get("email"));
            }
        }
        return "signup successfully - Welcome " + user;
    }

    private static String getName(Authentication authentication) {
        // Handle Oauth code flow and local authentication
        /*
        return Optional.of(authentication.getPrincipal())
                .filter(OidcUser.class::isInstance)
                .map(OidcUser.class::cast)
                .map(OidcUser::getEmail)
                .orElseGet(authentication::getName);
        */
        // Extension: Oauth code flow | Oauth implicit flow | local authentication
        return Optional.of(authentication.getPrincipal())
                .filter(principal -> principal instanceof OidcUser || principal instanceof JwtAuthenticationToken)
                // Handle OidcUser cases
                .map(OidcUser.class::cast)
                .map(OidcUser::getEmail)
                // Handle JwtAuthenticationToken cases
                .or(() -> Optional.of(authentication)
                        .filter(JwtAuthenticationToken.class::isInstance)
                        .map(JwtAuthenticationToken.class::cast)
                        .map(JwtAuthenticationToken::getPrincipal)
                        .filter(Jwt.class::isInstance)
                        .map(Jwt.class::cast)
                        .map(jwt -> jwt.getClaim("email").toString())
                )
                .orElseGet(authentication::getName);
    }
}
