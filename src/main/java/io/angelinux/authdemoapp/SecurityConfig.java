package io.angelinux.authdemoapp;

import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // Set configurer
        var configurer = new RobotLoginConfigurer()
                .password("beep-boop")
                .password("boop-beep");

        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/").permitAll()
//                .requestMatchers("/signup").permitAll()
                .requestMatchers("/error").permitAll()
                .requestMatchers("/favicon.ico").permitAll()
                .anyRequest().authenticated()
        );
        http.cors((cors) -> cors
                .configurationSource(corsConfigurationSource()));
        http.csrf(AbstractHttpConfigurer::disable);
        http.formLogin(Customizer.withDefaults());
        http.httpBasic(Customizer.withDefaults());
//        http.oauth2Login(
//                oauth2Configurer -> {
//                    oauth2Configurer.withObjectPostProcessor(
//                            new ObjectPostProcessor<AuthenticationProvider>() {
//                                @Override
//                                public <O extends AuthenticationProvider> O postProcess(O object) {
//                                    return (O) new RateLimitedAuthenticationProvider(object);
//                                }
//                            }
//                    );
//                }
//        );
        http.oauth2Login(Customizer.withDefaults());
        http.oauth2ResourceServer(oauth2 -> oauth2.jwt(jwt -> jwt.decoder(jwtDecoder())));
        http.with(configurer, Customizer.withDefaults());
        http.authenticationProvider(new AngelAuthenticationProvider());
        return http.build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.builder()
                        .username("user")
                        .password("{noop}password")
                        .authorities("ROLE_user")
                        .build()
        );
    }

    // ProviderManager produces an event when a user log in. So Here is the listener to those events
    @Bean
    public ApplicationListener<AuthenticationSuccessEvent> successListener() {
        return event -> {
            final String typeAuthentication = event.getAuthentication().getClass().getSimpleName();

            // Old school way to get username attribute (explicit casting)
            /*
            String username = event.getAuthentication().getName();
            if (event.getAuthentication().getPrincipal() instanceof OidcUser myOauthUser) {
                //OidcUser myOauthUser = (OidcUser) event.getAuthentication().getPrincipal(); // explicit casting
                username = myOauthUser.getEmail();
            }
             */

            // Modern way to get username attribute
            final String username = Optional.of(event.getAuthentication().getPrincipal())
                    .filter(OidcUser.class::isInstance)
                    .map(OidcUser.class::cast)
                    .map(OidcUser::getEmail)
                    .orElseGet(event.getAuthentication()::getName);

            System.out.println(
                    String.format("🎉 SUCCESS AUTHENTICATION [%s] %s ", typeAuthentication, username)
            );
        };
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOrigins(List.of("http://localhost:1234"));
        configuration.setAllowedMethods(Arrays.asList("GET","POST","PATCH", "PUT", "DELETE", "OPTIONS", "HEAD"));
        configuration.setAllowCredentials(true);
        configuration.setAllowedHeaders(Arrays.asList("Authorization", "Requestor-Type", "Content-Type"));
        configuration.setExposedHeaders(Arrays.asList("X-Get-Header"));
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

//    @Bean
//    public JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory() {
//        OidcIdTokenDecoderFactory idTokenDecoderFactory = new OidcIdTokenDecoderFactory();
//        idTokenDecoderFactory.setJwsAlgorithmResolver(clientRegistration -> MacAlgorithm.HS256);
//        return idTokenDecoderFactory;
//    }

    @Bean
    public JwtDecoder jwtDecoder() {
        // Configure NimbusJwtDecoder with Google's JWK set URI
        return NimbusJwtDecoder.withJwkSetUri("https://www.googleapis.com/oauth2/v3/certs").build();
    }
}
