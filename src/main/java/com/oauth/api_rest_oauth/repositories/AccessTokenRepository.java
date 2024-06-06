package com.oauth.api_rest_oauth.repositories;

import com.oauth.api_rest_oauth.models.AccessToken;
import jakarta.persistence.Id;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AccessTokenRepository extends JpaRepository<AccessToken, Long> {
}
