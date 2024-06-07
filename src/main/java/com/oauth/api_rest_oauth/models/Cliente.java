package com.oauth.api_rest_oauth.models;

import jakarta.persistence.*;

import java.util.List;

@Entity
@Table(name = "clientes")
public class Cliente {

    @Id
    @Column(name = "clientId")
    private String clientId;

    @Column(name = "clientSecret")
    private String clientSecret;

    @OneToMany(mappedBy = "cliente", cascade = CascadeType.ALL)
    private List<AccessToken> accessTokens;

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }

    public List<AccessToken> getAccessTokens() {
        return accessTokens;
    }

    public void setAccessTokens(List<AccessToken> accessTokens) {
        this.accessTokens = accessTokens;
    }
}
