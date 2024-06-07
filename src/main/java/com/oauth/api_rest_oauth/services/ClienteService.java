package com.oauth.api_rest_oauth.services;

import com.oauth.api_rest_oauth.models.Cliente;
import com.oauth.api_rest_oauth.repositories.ClienteRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@Transactional
public class ClienteService {

    @Autowired
    private ClienteRepository clienteRepository;

    public Cliente findByClientId(String clientId) {
        return clienteRepository.findById(clientId).orElseThrow(() -> new IllegalArgumentException("Cliente no encontrado"));
    }
}
