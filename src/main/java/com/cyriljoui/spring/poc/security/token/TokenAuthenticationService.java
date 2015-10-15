package com.cyriljoui.spring.poc.security.token;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.bind.DatatypeConverter;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;
import com.cyriljoui.spring.poc.security.user.User;
import com.cyriljoui.spring.poc.security.user.UserAuthentication;

@Service
public class TokenAuthenticationService {
	private static final long TEN_DAYS = 1000 * 60 * 60 * 24 * 10;

	@Autowired
	public TokenHandler tokenHandler;

	public void addAuthentication(HttpServletResponse response, UserAuthentication authentication) {
		final User user = authentication.getDetails();
		user.setExpires(System.currentTimeMillis() + TEN_DAYS);
		response.addHeader(HttpHeaders.AUTHORIZATION, tokenHandler.createTokenForUser(user));
	}

	public Authentication getAuthentication(HttpServletRequest request) {
        // Get the HTTP Authorization header from the request
        String authorizationHeader =
                request.getHeader(HttpHeaders.AUTHORIZATION);

        // Check if the HTTP Authorization header is present and formatted correctly
        if (authorizationHeader == null || !authorizationHeader.startsWith("Bearer ")) {
            return null;
            //throw new NotAuthorizedException("Authorization header must be provided");
        }

        // Extract the token from the HTTP Authorization header
        final String token = authorizationHeader.substring("Bearer".length()).trim();
        final User user = tokenHandler.parseUserFromToken(token);
        if (user != null) {
            return new UserAuthentication(user);
        }

		return null;
	}
}
