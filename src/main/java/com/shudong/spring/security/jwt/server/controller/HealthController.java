package com.shudong.spring.oauth2.server.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Properties;

@RestController
@RequestMapping("/")
public class HealthController {

    @GetMapping(path = "/health")
    public Properties health() {
        return System.getProperties();
    }

}
