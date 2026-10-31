package com.piiguard.action;

import com.piiguard.detect.Finding;

public class RedactAction implements Action {
    @Override public ActionType type() { return ActionType.REDACT; }
    @Override public String apply(Finding f) { return "[REDACTED:" + f.type() + "]"; }
}
