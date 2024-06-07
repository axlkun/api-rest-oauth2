package com.oauth.api_rest_oauth.models;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "access_tokens")
public class AccessToken {

    @Id
    private String jti;

    private String aud;
    private Instant exp;
    private Instant iat;
    private String scope;

    @ManyToOne
    @JoinColumn(name = "clientId", nullable = false)
    private Cliente cliente;

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public Instant getExp() {
        return exp;
    }

    public void setExp(Instant exp) {
        this.exp = exp;
    }

    public Instant getIat() {
        return iat;
    }

    public void setIat(Instant iat) {
        this.iat = iat;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public Cliente getCliente() {
        return cliente;
    }

    public void setCliente(Cliente cliente) {
        this.cliente = cliente;
    }
}
