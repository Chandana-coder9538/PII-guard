package com.piiguard.engine;

import com.piiguard.action.ActionType;
import com.piiguard.detect.PiiType;

import java.util.List;

/** One recipe step. If columns is non-empty the rule applies to those whole columns only (CSV);
 *  otherwise the regex detector for the type runs over all text. */
public record RuleSpec(PiiType type, ActionType action, List<String> columns) {
    public RuleSpec {
        if (columns == null) columns = List.of();
    }
}
