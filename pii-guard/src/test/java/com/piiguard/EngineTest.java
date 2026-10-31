package com.piiguard;

import com.piiguard.crypto.AesGcm;
import com.piiguard.crypto.Hmac;
import com.piiguard.detect.DetectorRegistry;
import com.piiguard.detect.VerhoeffValidator;
import com.piiguard.engine.AuditCollector;
import com.piiguard.engine.Recipe;
import com.piiguard.engine.RecipeEngine;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class EngineTest {
    private final Map<String, String> vault = new HashMap<>();
    private final RecipeEngine engine = new RecipeEngine(new DetectorRegistry(), new Hmac("k"),
        (type, value) -> vault.computeIfAbsent(type + value, k -> "TKN_" + type + "_" + vault.size()));

    @Test void masksEverythingAndReportsCleanResidual() {
        String aad = VerhoeffValidator.withCheckDigit("23456789012");
        String in = "mail ravi@example.com phone 9876543210 aadhaar " + aad + " pan ABCDE1234F";
        AuditCollector audit = new AuditCollector();
        String out = engine.process(in, Recipe.defaultRecipe(), null, 1, audit);

        assertFalse(out.contains("ravi@example.com"));
        assertFalse(out.contains("9876543210"));
        assertFalse(out.contains(aad));
        assertFalse(out.contains("ABCDE1234F"));
        assertEquals(4, audit.total());
        assertEquals(0, audit.residualFindings());
    }

    @Test void hashIsDeterministicAndTokenIsStable() {
        String in = "ravi@example.com";
        String a = engine.process(in, Recipe.defaultRecipe(), null, 1, new AuditCollector());
        String b = engine.process(in, Recipe.defaultRecipe(), null, 2, new AuditCollector());
        assertEquals(a, b);
    }

    @Test void nameColumnIsMaskedWholeCell() {
        String out = engine.process("Ravi Kumar", Recipe.defaultRecipe(), "customer_name", 1, new AuditCollector());
        assertEquals("R*** K****", out);
    }

    @Test void auditNeverContainsRawValues() {
        AuditCollector audit = new AuditCollector();
        engine.process("ravi@example.com", Recipe.defaultRecipe(), null, 1, audit);
        audit.records().forEach(r -> assertFalse(r.fingerprint().contains("ravi")));
        assertEquals(8, audit.records().get(0).fingerprint().length());
    }

    @Test void aesRoundTrip() {
        AesGcm aes = new AesGcm("secret");
        assertEquals("hello", aes.decrypt(aes.encrypt("hello")));
        assertThrows(IllegalStateException.class, () -> new AesGcm("other").decrypt(aes.encrypt("hello")));
    }
}
