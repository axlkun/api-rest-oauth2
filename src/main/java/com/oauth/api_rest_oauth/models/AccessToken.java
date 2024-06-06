package com.oauth.api_rest_oauth.models;

import jakarta.persistence.*;

import java.time.Instant;

@Entity
@Table(name = "access_tokens")
public class AccessToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String sub;
    private String aud;
    private Instant nbf;
    private Instant exp;
    private Instant iat;
    private String scope;
    private String iss;
    private String jti;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getSub() {
        return sub;
    }

    public void setSub(String sub) {
        this.sub = sub;
    }

    public String getAud() {
        return aud;
    }

    public void setAud(String aud) {
        this.aud = aud;
    }

    public Instant getNbf() {
        return nbf;
    }

    public void setNbf(Instant nbf) {
        this.nbf = nbf;
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

    public String getIss() {
        return iss;
    }

    public void setIss(String iss) {
        this.iss = iss;
    }

    public String getJti() {
        return jti;
    }

    public void setJti(String jti) {
        this.jti = jti;
    }
}
