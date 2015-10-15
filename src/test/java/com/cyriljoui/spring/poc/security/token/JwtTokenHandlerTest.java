package com.cyriljoui.spring.poc.security.token;

import com.cyriljoui.spring.poc.security.user.User;
import com.cyriljoui.spring.poc.security.user.UserRole;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.impl.crypto.MacProvider;
import org.junit.Before;
import org.junit.Test;

import javax.xml.bind.DatatypeConverter;
import java.security.Key;
import java.util.Date;

import static org.junit.Assert.*;

public class JwtTokenHandlerTest {

    private JwtTokenHandler tokenHandler;

    @Before
    public void init() {
        Key key = MacProvider.generateKey();
        byte[] encoded = key.getEncoded();
        System.out.println("encoded64: " + DatatypeConverter.printBase64Binary(encoded));
        tokenHandler = new JwtTokenHandler(encoded);
    }

    @Test
    public void testRoundTrip_ProperData() {
        final User user = new User("Robbert", new Date(new Date().getTime() + 10000));
        user.grantRole(UserRole.ADMIN);
        user.grantRole(UserRole.ANNOT);

        String tokenForUser = tokenHandler.createTokenForUser(user);
        System.out.println("tokenForUser: " + tokenForUser);
        final User parsedUser = tokenHandler.parseUserFromToken(tokenForUser);

        assertEquals(user.getUsername(), parsedUser.getUsername());
        assertTrue(parsedUser.hasRole(UserRole.ADMIN));
        assertTrue(parsedUser.hasRole(UserRole.ANNOT));
    }

    @Test
    public void testExpiredToken() {
        final User user = new User("Robbert", new Date(new Date().getTime() + 1));
        user.grantRole(UserRole.ADMIN);
        user.grantRole(UserRole.ANNOT);

        String tokenForUser = tokenHandler.createTokenForUser(user);
        try {
            Thread.sleep(1000);
        } catch (InterruptedException e) {
            // No need to do anything
        }
        try {
            final User parsedUser = tokenHandler.parseUserFromToken(tokenForUser);
            fail("Token should be expired => must throw ExpiredJwtException!");
        } catch (ExpiredJwtException e) {
            assertNotNull(e);
        }
    }
}
