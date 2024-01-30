package io.angelinux.authdemoapp;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

public class RobotFilter extends OncePerRequestFilter {

    private final String ROBOT_HEADER = "x-robot-password";

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
        String password = request.getHeader("x-robot-password"); // be careful: password could be null
        if (!"beep-boop".equals(password)) {
            // NO 👎🏻 Deny access
            response.setStatus(HttpStatus.FORBIDDEN.value());
            response.setCharacterEncoding("utf-8");
            response.setHeader("Content-type", "text/plain;charset=utf-8");
            response.getWriter().println("You are not Ms Robot 🤖❌");
            return;
        }
        // 2. Do the rest (continue)
        // OK 👍🏻: create `Authentication` and set in SecurityContext
        SecurityContext newContext = SecurityContextHolder.createEmptyContext();
        newContext.setAuthentication(new RobotAuthentication());
        SecurityContextHolder.setContext(newContext);
        filterChain.doFilter(request, response);
    }
}
