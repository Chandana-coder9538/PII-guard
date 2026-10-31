package com.piiguard.vault;

import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.piiguard.action.TokenStore;
import com.piiguard.crypto.AesGcm;
import com.piiguard.crypto.Hmac;
import com.piiguard.detect.PiiType;

/** Deterministic tokenization: same value -> same token. Original value stored AES-GCM encrypted. */
@Service
public class TokenVault implements TokenStore {
    private final VaultRepository repo;
    private final Hmac hmac;
    private final AesGcm aes;

    public TokenVault(VaultRepository repo, Hmac hmac, AesGcm aes) {
        this.repo = repo; this.hmac = hmac; this.aes = aes;
    }

    @Override
    @Transactional
    public synchronized String tokenFor(PiiType type, String value) {
        String h = hmac.hex(type.name() + ":" + value);
        Optional<VaultEntry> existing = repo.findByValueHmac(h);
        if (existing.isPresent()) return existing.get().getToken();
        String token = "TKN_" + type.name() + "_" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);
        repo.save(new VaultEntry(token, type.name(), h, aes.encrypt(value)));
        return token;
    }

    @Transactional(readOnly = true)
    public Optional<String> detokenize(String token) {
        return repo.findByToken(token).map(e -> aes.decrypt(e.getValueCipher()));
    }

    @Transactional(readOnly = true)
    public Optional<VaultEntry> find(String token) { return repo.findByToken(token); }
}