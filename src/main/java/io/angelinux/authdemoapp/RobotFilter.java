package io.angelinux.authdemoapp;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

public class RobotFilter extends OncePerRequestFilter {

    private final String ROBOT_HEADER = "x-robot-password";
    private final AuthenticationManager authenticationManager;

    public RobotFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        // 0. Should we execute the filter?
        if (!Collections.list(request.getHeaderNames()).contains(ROBOT_HEADER)) {
            // This kind of request it's not my business.
            filterChain.doFilter(request, response);
            return;
        }

        System.out.println("🤖 Hello from the Robot Filter");
        // 1. Authentication decision
        String password = request.getHeader(ROBOT_HEADER); // be careful: password could be null
        RobotAuthentication authRequest = RobotAuthentication.unauthenticated(password);

        try {
            Authentication authentication = authenticationManager.authenticate(authRequest); // if this verification fails -> throws an Exception
            // OK Legit Access 👍🏻: create `Authentication` and set in SecurityContext
            // 2. Do the rest (continue)
            SecurityContext newContext = SecurityContextHolder.createEmptyContext();
            newContext.setAuthentication(authentication);
            SecurityContextHolder.setContext(newContext);
            filterChain.doFilter(request, response);
        } catch (AuthenticationException e) {
            // NO 👎🏻 Deny access
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setCharacterEncoding("utf-8");
            response.setHeader("Content-type", "text/plain;charset=utf-8");
            response.getWriter().println(e.getMessage());
        }
    }
}
