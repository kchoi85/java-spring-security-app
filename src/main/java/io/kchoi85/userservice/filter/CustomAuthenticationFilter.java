package io.kchoi85.userservice.filter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.algorithms.Algorithm;

import io.kchoi85.userservice.model.User;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CustomAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;

    public CustomAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) {
        String username = request.getParameter("username");
        String password = request.getParameter("password");
        log.info("Attempting authentication with username: {}", username);

        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                username,
                password);
        return authenticationManager.authenticate(authenticationToken);
    }

    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response,
            Authentication authResult) {
        log.info("Successful authentication with username: {}", authResult.getName());
        User user = (User) authResult.getPrincipal();

        // JWT token algorithm
        Algorithm algorithm = Algorithm.HMAC256("secret");
    }
}
