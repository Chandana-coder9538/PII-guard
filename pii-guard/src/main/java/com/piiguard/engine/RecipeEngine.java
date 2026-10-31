package com.piiguard.engine;

import com.piiguard.action.*;
import com.piiguard.crypto.Hmac;
import com.piiguard.detect.DetectorRegistry;
import com.piiguard.detect.Finding;
import com.piiguard.detect.PiiType;

import java.util.*;

/** detect -> resolve overlaps -> apply action -> audit -> residual re-scan. */
public class RecipeEngine {
    private final DetectorRegistry registry;
    private final Map<ActionType, Action> actions = new EnumMap<>(ActionType.class);
    private final Hmac hmac;

    public RecipeEngine(DetectorRegistry registry, Hmac hmac, TokenStore tokens) {
        this.registry = registry;
        this.hmac = hmac;
        for (Action a : List.of(new MaskAction(), new HashAction(hmac), new RedactAction(), new TokenizeAction(tokens)))
            actions.put(a.type(), a);
    }

    /** Process a free-text value (log line, text blob, or a CSV cell). column may be null. */
    public String process(String text, Recipe recipe, String column, int row, AuditCollector audit) {
        if (text == null || text.isEmpty()) return text;

        Map<Finding, ActionType> chosen = new IdentityHashMap<>();
        List<Finding> all = new ArrayList<>();

        for (RuleSpec rule : recipe.rules()) {
            if (!rule.columns().isEmpty()) {
                // column-driven rule (e.g. NAME): whole cell
                if (column != null && rule.columns().stream().anyMatch(c -> c.equalsIgnoreCase(column))) {
                    Finding f = new Finding(rule.type(), 0, text.length(), text);
                    all.add(f);
                    chosen.put(f, rule.action());
                }
            } else {
                for (Finding f : registry.detect(rule.type(), text)) {
                    all.add(f);
                    chosen.put(f, rule.action());
                }
            }
        }

        // overlap resolution: earliest start wins, then the longest match
        all.sort(Comparator.comparingInt(Finding::start).thenComparing(Comparator.comparingInt(Finding::length).reversed()));
        List<Finding> kept = new ArrayList<>();
        int lastEnd = -1;
        for (Finding f : all) {
            if (f.start() >= lastEnd) { kept.add(f); lastEnd = f.end(); }
        }

        StringBuilder sb = new StringBuilder(text);
        for (int i = kept.size() - 1; i >= 0; i--) {          // right-to-left keeps offsets valid
            Finding f = kept.get(i);
            ActionType at = chosen.get(f);
            String replacement = actions.get(at).apply(f);
            sb.replace(f.start(), f.end(), replacement);
            audit.record(new AuditRecord(row, column, f.type().name(), at.name(),
                hmac.hex(f.value()).substring(0, 8)));
        }
        String masked = sb.toString();

        // residual scan: any regex-detectable PII still present in the output?
        int residual = 0;
        for (RuleSpec rule : recipe.rules())
            if (rule.columns().isEmpty()) residual += registry.detect(rule.type(), masked).size();
        audit.addResidual(residual);
        return masked;
    }

    /** Dry run: report what would be detected, with no raw values returned. */
    public List<Map<String, Object>> detectOnly(String text, Set<PiiType> types) {
        List<Map<String, Object>> out = new ArrayList<>();
        for (PiiType t : types)
            for (Finding f : registry.detect(t, text))
                out.add(Map.of("type", t.name(), "start", f.start(), "end", f.end(),
                    "fingerprint", hmac.hex(f.value()).substring(0, 8)));
        out.sort(Comparator.comparingInt(m -> (Integer) m.get("start")));
        return out;
    }
}
