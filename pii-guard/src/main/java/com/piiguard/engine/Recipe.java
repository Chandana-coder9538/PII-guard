package com.piiguard.engine;

import com.piiguard.action.ActionType;
import com.piiguard.detect.PiiType;

import java.util.List;

public record Recipe(String name, List<RuleSpec> rules) {
    public static Recipe defaultRecipe() {
        return new Recipe("vendor-share-v1", List.of(
            new RuleSpec(PiiType.AADHAAR, ActionType.TOKENIZE, List.of()),
            new RuleSpec(PiiType.PHONE, ActionType.MASK, List.of()),
            new RuleSpec(PiiType.EMAIL, ActionType.HASH, List.of()),
            new RuleSpec(PiiType.PAN, ActionType.REDACT, List.of()),
            new RuleSpec(PiiType.CARD, ActionType.MASK, List.of()),
            new RuleSpec(PiiType.IFSC, ActionType.REDACT, List.of()),
            new RuleSpec(PiiType.IPV4, ActionType.HASH, List.of()),
            new RuleSpec(PiiType.NAME, ActionType.MASK, List.of("name", "customer_name", "full_name"))
        ));
    }
}
