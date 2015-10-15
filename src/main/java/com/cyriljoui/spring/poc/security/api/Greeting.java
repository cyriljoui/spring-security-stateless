package com.cyriljoui.spring.poc.security.api;

public class Greeting {
    private final String text;

    public Greeting(String text) {
        this.text = text;
    }

    public String getText() {
        return text;
    }

}
