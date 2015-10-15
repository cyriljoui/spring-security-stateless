package com.cyriljoui.spring.poc.security.token;

import com.cyriljoui.spring.poc.security.user.User;
import com.cyriljoui.spring.poc.security.user.UserRole;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.util.*;


public class JwtTokenHandler implements TokenHandler {
    public static final String CLAIM_ROLES = "roles";
    private final byte[] secret;

    public JwtTokenHandler(byte[] secret) {
        this.secret = secret;
    }

    public User parseUserFromToken(String token) {
        Claims body = Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
        String username = body
                .getSubject();
        List<String> roles = (List<String>) body.get(CLAIM_ROLES);

        // Create user object from user token one
        User user = new User();
        user.setUsername(username);
        user.setExpires(body.getExpiration().getTime());

        // Set roles
        for (String role : roles) {
            user.grantRole(UserRole.valueOf(role));
        }
        return user;
    }

    public String createTokenForUser(User user) {
        Map<String, Object> claims = new HashMap<String, Object>();
        claims.put(Claims.SUBJECT, user.getUsername());
        claims.put(CLAIM_ROLES, user.getRoles());
        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(new Date(user.getExpires()))
                .signWith(SignatureAlgorithm.HS512, secret)
                .compact();
    }

    private String toJSON(User user) {
        try {
            return new ObjectMapper().writeValueAsString(user);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(e);
        }
    }
}
