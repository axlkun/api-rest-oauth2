package com.oauth.api_rest_oauth.controllers;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api")
public class ApiController {

    @GetMapping("/read")
    public ResponseEntity<String> readData(Authentication authentication) {
        return ResponseEntity.ok("Data read successfully. " + authentication.getAuthorities());
    }

    @PostMapping("/write")
    public ResponseEntity<String> writeData(Authentication authentication) {
        return ResponseEntity.ok("Data written successfully. " + authentication.getAuthorities());
    }

}
