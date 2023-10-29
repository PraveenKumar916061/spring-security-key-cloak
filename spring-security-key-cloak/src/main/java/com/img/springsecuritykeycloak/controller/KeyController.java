package com.img.springsecuritykeycloak.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/key")
public class KeyController {

    @GetMapping("/message")
    @PreAuthorize("hasRole('client_admin')")
    public String getMessage() {
        return "Hii api key. . . admin";
    }

    @GetMapping("/message/hello")
    @PreAuthorize("hasRole('client_user')")
    public String getHello() {
        return "Hello api key.... user";
    }
}
