package com.oauth.api_rest_oauth.services;

import com.oauth.api_rest_oauth.models.AccessToken;
import com.oauth.api_rest_oauth.repositories.AccessTokenRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

@Service
public class AccessTokenService {

    @Autowired
    private AccessTokenRepository accessTokenRepository;

    public void saveAccessToken(AccessToken accessToken) {
        accessTokenRepository.save(accessToken);
    }
}
