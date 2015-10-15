package com.cyriljoui.spring.poc.security.token;

import java.util.Date;
import java.util.Set;

public class CustomUserToken {
    private String sub;

    private Set<String> roles;

    private long expires;

    public CustomUserToken() {
    }

    public CustomUserToken(String sub, Set<String> roles, long expires) {
        this.sub = sub;
        this.roles = roles;
        this.expires = expires;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public Set<String> getRoles() {
        return roles;
    }

    public void setRoles(Set<String> roles) {
        this.roles = roles;
    }

    public long getExpires() {
        return expires;
    }

    public void setExpires(long expires) {
        this.expires = expires;
    }
}
