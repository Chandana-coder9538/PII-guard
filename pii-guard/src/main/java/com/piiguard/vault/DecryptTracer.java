package com.piiguard.vault;

import com.piiguard.crypto.AesGcm;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.*;

/**
 * Runs the real detokenize flow and reports each step, for the UI's Decryption lab.
 * Scenarios "wrong-key" and "tampered" run on in-memory copies only; the stored row is never changed.
 * The response never contains the key. Plaintext is returned only for a real, authorized decryption.
 */
@Service
public class DecryptTracer {
    private static final Logger log = LoggerFactory.getLogger(DecryptTracer.class);
    private static final String[][] STEPS = {
        {"authorize", "Check the caller"}, {"lookup", "Find the vault row"}, {"parse", "Split the stored bytes"},
        {"key", "Load the key"}, {"decrypt", "Verify the tag, then decrypt"}};

    public record Step(String id, String title, String status, String explain, Map<String, Object> data) {}
    public record Trace(String token, String scenario, String outcome, List<Step> steps, String plaintext) {}

    private final TokenVault vault;
    private final AesGcm aes;
    private final String adminKey;

    public DecryptTracer(TokenVault vault, AesGcm aes, @Value("${piiguard.admin-key}") String adminKey) {
        this.vault = vault; this.aes = aes; this.adminKey = adminKey;
    }

    public Trace trace(String token, String scenario, String apiKey) {
        String sc = "wrong-key".equals(scenario) || "tampered".equals(scenario) ? scenario : "authorized";
        String t = token == null ? "" : token.trim();
        List<Step> steps = new ArrayList<>();

        boolean granted = apiKey != null && MessageDigest.isEqual(sha(apiKey), sha(adminKey));
        steps.add(step(0, granted, granted
            ? "The X-API-Key matches the admin key, so this caller may reverse tokens."
            : "The X-API-Key is missing or wrong. Decryption stops before the encrypted bytes are read.",
            m("method", "constant-time compare of SHA-256(X-API-Key) and SHA-256(admin key)", "granted", granted)));
        if (!granted) return end(t, sc, "DENIED", steps, null);

        Optional<VaultEntry> found = vault.find(t);
        if (found.isEmpty()) {
            steps.add(step(1, false, "No vault row has this token, so there is nothing to decrypt.", m("lookup", "unique index on token")));
            return end(t, sc, "UNKNOWN_TOKEN", steps, null);
        }
        VaultEntry row = found.get();
        steps.add(step(1, true, "The token is only a random label. The row it points to holds the encrypted original.",
            m("piiType", row.getPiiType(), "storedBytes", row.getValueCipher().length, "createdAt", String.valueOf(row.getCreatedAt()))));

        AesGcm.Parts p = aes.split(row.getValueCipher());
        byte[] ct = p.ciphertext(), tag = p.tag();
        Map<String, Object> parse = m("layout", "12-byte IV | ciphertext | 16-byte tag");
        if ("tampered".equals(sc)) {
            (ct.length > 0 ? ct : tag)[0] ^= 1;   // copies from split(): the stored row is untouched
            parse.put("demoNote", "Demo only: one bit of the " + (ct.length > 0 ? "ciphertext" : "tag") + " was flipped in a memory copy.");
        }
        parse.put("ivHex", hex(p.iv())); parse.put("ciphertextHex", hex(ct)); parse.put("tagHex", hex(tag));
        steps.add(step(2, true, "The IV is a fresh random value per encryption. The tag is the seal that proves nothing changed.", parse));

        AesGcm used = "wrong-key".equals(sc) ? new AesGcm("a-passphrase-that-is-not-the-vault-secret") : aes;
        steps.add(step(3, true, "The key is rebuilt from the server secret. Only a fingerprint is shown; the key never leaves the server.",
            m("derivation", "AES-256 key = SHA-256(passphrase)",
              "source", "wrong-key".equals(sc) ? "Demo: a passphrase that is not the vault secret" : "PIIGUARD_VAULT_SECRET on the server",
              "keyFingerprint", used.keyFingerprint())));

        try {
            String plain = used.decrypt(AesGcm.join(new AesGcm.Parts(p.iv(), ct, tag)));
            steps.add(step(4, true, "GCM recomputed the tag from the IV and ciphertext and it matched, so the plaintext was released.",
                m("algorithm", "AES/GCM/NoPadding", "tagBits", 128, "plaintextBytes", plain.getBytes(StandardCharsets.UTF_8).length)));
            return end(t, sc, "DECRYPTED", steps, "authorized".equals(sc) ? plain : null);
        } catch (IllegalStateException e) {
            steps.add(step(4, false, "The recomputed tag did not match the stored tag, so GCM released nothing. It fails closed.",
                m("algorithm", "AES/GCM/NoPadding", "tagBits", 128, "error", "AEADBadTagException", "plaintextReleased", false)));
            return end(t, sc, "TAG_MISMATCH", steps, null);
        }
    }

    private Trace end(String t, String sc, String outcome, List<Step> steps, String plain) {
        for (int i = steps.size(); i < STEPS.length; i++)
            steps.add(new Step(STEPS[i][0], STEPS[i][1], "skipped", "Not reached.", Map.of()));
        log.info("vault.trace token={} scenario={} outcome={}", t.replaceAll("[\\r\\n]", ""), sc, outcome);
        return new Trace(t, sc, outcome, steps, plain);
    }

    private static Step step(int i, boolean ok, String explain, Map<String, Object> data) {
        return new Step(STEPS[i][0], STEPS[i][1], ok ? "ok" : "fail", explain, data);
    }

    private static Map<String, Object> m(Object... kv) {
        Map<String, Object> out = new LinkedHashMap<>();
        for (int i = 0; i < kv.length; i += 2) out.put((String) kv[i], kv[i + 1]);
        return out;
    }

    private static String hex(byte[] b) { return HexFormat.of().formatHex(b); }

    private static byte[] sha(String s) {
        try { return MessageDigest.getInstance("SHA-256").digest(s.getBytes(StandardCharsets.UTF_8)); }
        catch (GeneralSecurityException e) { throw new IllegalStateException(e); }
    }
}