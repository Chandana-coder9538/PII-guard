package com.piiguard.engine;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.EnumMap;
import java.util.IdentityHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.piiguard.action.Action;
import com.piiguard.action.ActionType;
import com.piiguard.action.HashAction;
import com.piiguard.action.MaskAction;
import com.piiguard.action.RedactAction;
import com.piiguard.action.TokenStore;
import com.piiguard.action.TokenizeAction;
import com.piiguard.crypto.Hmac;
import com.piiguard.detect.DetectorRegistry;
import com.piiguard.detect.Finding;
import com.piiguard.detect.PiiType;

/** detect -> resolve overlaps -> apply action -> audit -> residual re-scan. */
public class RecipeEngine {
    private final DetectorRegistry registry;
    private final Map<ActionType, Action> actions = new EnumMap<>(ActionType.class);
    private final Hmac hmac;
    private final Map<String, Pattern> patterns = new ConcurrentHashMap<>();

    public RecipeEngine(DetectorRegistry registry, Hmac hmac, TokenStore tokens) {
        this.registry = registry;
        this.hmac = hmac;
        for (Action a : List.of(new MaskAction(), new HashAction(hmac), new RedactAction(), new TokenizeAction(tokens)))
            actions.put(a.type(), a);
    }

    public String process(String text, Recipe recipe, String column, int row, AuditCollector audit) {
        return process(text, recipe, column, row, audit, List.of());
    }

    /** Process a free-text value (log line, text blob, or a CSV cell). column may be null.
     *  knownNames: names from this row's name columns, to be scrubbed from the other columns. */
    public String process(String text, Recipe recipe, String column, int row, AuditCollector audit, List<String> knownNames) {
        if (text == null || text.isEmpty()) return text;

        Map<Finding, ActionType> chosen = new IdentityHashMap<>();
        List<Finding> all = new ArrayList<>();

        for (RuleSpec rule : recipe.rules()) {
            boolean inColumn = inColumn(rule, column);
            if (!rule.patterns().isEmpty()) {
                // keyword / regex rule for free text (limited to the listed columns, if any)
                if (rule.columns().isEmpty() || inColumn)
                    for (String p : rule.patterns())
                        addMatches(all, chosen, rule, text, pattern(p));
            } else if (!rule.columns().isEmpty()) {
                if (inColumn) {
                    // column-driven rule (e.g. NAME): whole cell
                    Finding f = new Finding(rule.type(), 0, text.length(), text);
                    all.add(f);
                    chosen.put(f, rule.action());
                } else if (rule.type() == PiiType.NAME) {
                    // the same person's name written inside another column (e.g. notes)
                    for (String name : knownNames)
                        addMatches(all, chosen, rule, text, pattern("\u0000name:" + name.toLowerCase(Locale.ROOT)));
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

        // residual scan: any regex-detectable PII or keyword still present in the output?
        int residual = 0;
        for (RuleSpec rule : recipe.rules()) {
            if (!rule.patterns().isEmpty()) {
                if (rule.columns().isEmpty() || inColumn(rule, column))
                    for (String p : rule.patterns()) residual += count(pattern(p), masked);
            } else if (rule.columns().isEmpty()) {
                residual += registry.detect(rule.type(), masked).size();
            }
        }
        audit.addResidual(residual);
        return masked;
    }

    /** Words (3+ letters) from this row's NAME-column cells, so they can be scrubbed from free-text columns. */
    public List<String> knownNames(Recipe recipe, Map<String, String> row) {
        Set<String> terms = new LinkedHashSet<>();
        for (RuleSpec rule : recipe.rules()) {
            if (rule.type() != PiiType.NAME || rule.columns().isEmpty() || !rule.patterns().isEmpty()) continue;
            for (Map.Entry<String, String> e : row.entrySet()) {
                if (e.getValue() == null || rule.columns().stream().noneMatch(c -> c.equalsIgnoreCase(e.getKey()))) continue;
                for (String w : e.getValue().trim().split("\\s+"))
                    if (w.codePointCount(0, w.length()) >= 3) terms.add(w);
            }
        }
        return new ArrayList<>(terms);
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

    private static boolean inColumn(RuleSpec rule, String column) {
        return column != null && rule.columns().stream().anyMatch(c -> c.equalsIgnoreCase(column));
    }

    private void addMatches(List<Finding> all, Map<Finding, ActionType> chosen, RuleSpec rule, String text, Pattern p) {
        Matcher m = p.matcher(text);
        while (m.find()) {
            if (m.end() == m.start()) continue;
            Finding f = new Finding(rule.type(), m.start(), m.end(), m.group());
            all.add(f);
            chosen.put(f, rule.action());
        }
    }

    private static int count(Pattern p, String text) {
        int n = 0;
        Matcher m = p.matcher(text);
        while (m.find()) if (m.end() > m.start()) n++;
        return n;
    }

    /** Keyword/regex patterns are case-insensitive. A key starting with \u0000name: is a literal whole-word name. */
    private Pattern pattern(String key) {
        return patterns.computeIfAbsent(key, k -> {
            int flags = Pattern.CASE_INSENSITIVE | Pattern.UNICODE_CASE;
            if (k.startsWith("\u0000name:"))
                return Pattern.compile("(?<![\\p{L}\\p{N}])" + Pattern.quote(k.substring(6)) + "(?![\\p{L}\\p{N}])", flags);
            return Pattern.compile(k, flags);
        });
    }
}