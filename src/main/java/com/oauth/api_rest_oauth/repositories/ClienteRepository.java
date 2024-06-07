package com.oauth.api_rest_oauth.repositories;

import com.oauth.api_rest_oauth.models.Cliente;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ClienteRepository extends JpaRepository<Cliente, String> {
    Optional<Cliente> findByClientId(String clientId);
}
