package com.cyriljoui.spring.poc.security.config;

import com.cyriljoui.spring.poc.security.token.CustomTokenHandler;
import com.cyriljoui.spring.poc.security.token.TokenHandler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.xml.bind.DatatypeConverter;

//@Configuration
public class CustomTokenConfig {

    @Bean
    public TokenHandler tokenHandler(@Value("${token.secret}") String secret) {
        return new CustomTokenHandler(DatatypeConverter.parseBase64Binary(secret));
    }

}
