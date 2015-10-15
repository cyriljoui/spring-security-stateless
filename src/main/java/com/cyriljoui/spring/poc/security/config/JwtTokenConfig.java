package com.cyriljoui.spring.poc.security.config;

import com.cyriljoui.spring.poc.security.token.CustomTokenHandler;
import com.cyriljoui.spring.poc.security.token.JwtTokenHandler;
import com.cyriljoui.spring.poc.security.token.TokenHandler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.xml.bind.DatatypeConverter;

@Configuration
public class JwtTokenConfig {

    @Bean
    public TokenHandler tokenHandler(@Value("${token.jwt.secret}") String secret) {
        return new JwtTokenHandler(DatatypeConverter.parseBase64Binary(secret));
    }

}
