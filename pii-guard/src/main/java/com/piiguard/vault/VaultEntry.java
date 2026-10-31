package com.piiguard.vault;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "vault_entry", indexes = {
    @Index(name = "ix_vault_hmac", columnList = "valueHmac", unique = true),
    @Index(name = "ix_vault_token", columnList = "token", unique = true)})
public class VaultEntry {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) private Long id;
    @Column(nullable = false) private String token;
    @Column(nullable = false) private String piiType;
    @Column(nullable = false) private String valueHmac;
    @Column(nullable = false, length = 4096) private byte[] valueCipher;
    private Instant createdAt = Instant.now();

    protected VaultEntry() {}
    public VaultEntry(String token, String piiType, String valueHmac, byte[] valueCipher) {
        this.token = token; this.piiType = piiType; this.valueHmac = valueHmac; this.valueCipher = valueCipher;
    }
    public String getToken() { return token; }
    public String getPiiType() { return piiType; }
    public byte[] getValueCipher() { return valueCipher; }
}
