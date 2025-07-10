package com.example.vulnerable.controller;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

@RestController
public class VulnerableController {
    
    private static final Logger logger = LogManager.getLogger(VulnerableController.class.getName());
    
    @GetMapping("/")
    public String main(HttpServletRequest request) {
        logger.info("Received request with User-Agent");
        String userAgent = request.getHeader("User-Agent");
        logger.info("User-Agent: " + userAgent);
        return "User-Agent: " + userAgent;
    }
} 