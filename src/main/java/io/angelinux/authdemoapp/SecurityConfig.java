package io.angelinux.authdemoapp;

import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationEventPublisher;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

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
                .requestMatchers("/error").permitAll()
                .requestMatchers("/favicon.ico").permitAll()
                .anyRequest().authenticated()
        );
        http.formLogin(Customizer.withDefaults());
        http.httpBasic(Customizer.withDefaults());
        http.oauth2Login(Customizer.withDefaults());
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
}
