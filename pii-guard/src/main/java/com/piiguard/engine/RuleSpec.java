package com.piiguard.engine;

import java.util.List;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;

import com.piiguard.action.ActionType;
import com.piiguard.detect.PiiType;

/** One recipe step.
 *  - patterns non-empty: keyword/regex rule for free text (case-insensitive), limited to columns if any are listed.
 *  - else columns non-empty: the rule applies to those whole columns (CSV).
 *  - else: the regex detector for the type runs over all text. */
public record RuleSpec(PiiType type, ActionType action, List<String> columns, List<String> patterns) {
    public RuleSpec {
        if (columns == null) columns = List.of();
        if (patterns == null) patterns = List.of();
        if (patterns.size() > 50) throw new IllegalArgumentException("At most 50 patterns per rule");
        for (String p : patterns) {
            if (p == null || p.isBlank() || p.length() > 200)
                throw new IllegalArgumentException("Each pattern must be 1 to 200 characters");
            try { Pattern.compile(p); }
            catch (PatternSyntaxException e) { throw new IllegalArgumentException("Invalid pattern: " + p); }
        }
    }

    public RuleSpec(PiiType type, ActionType action, List<String> columns) { this(type, action, columns, List.of()); }
}