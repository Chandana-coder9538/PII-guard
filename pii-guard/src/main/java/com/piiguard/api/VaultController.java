package com.piiguard.api;

import com.piiguard.api.Dtos.DetokenizeRequest;
import com.piiguard.vault.TokenVault;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.Map;

@RestController
@RequestMapping("/api/vault")
public class VaultController {
    private final TokenVault vault;
    private final String adminKey;

    public VaultController(TokenVault vault, @Value("${piiguard.admin-key}") String adminKey) {
        this.vault = vault; this.adminKey = adminKey;
    }

    /** Reversal is privileged: requires the X-API-Key header. (Replace with Spring Security roles for production.) */
    @PostMapping("/detokenize")
    public Map<String, String> detokenize(@RequestHeader(value = "X-API-Key", required = false) String key,
                                          @RequestBody DetokenizeRequest req) {
        if (key == null || !java.security.MessageDigest.isEqual(key.getBytes(), adminKey.getBytes()))
            throw new ResponseStatusException(HttpStatus.FORBIDDEN, "invalid API key");
        String value = vault.detokenize(req.token())
            .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "unknown token"));
        return Map.of("token", req.token(), "value", value);
    }
}
