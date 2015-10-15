package com.cyriljoui.spring.poc.security.token;


import com.cyriljoui.spring.poc.security.user.User;

public interface TokenHandler {

    User parseUserFromToken(String token);

    String createTokenForUser(User user);

}
