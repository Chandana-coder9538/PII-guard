package com.piiguard.action;

import com.piiguard.crypto.Hmac;
import com.piiguard.detect.Finding;

/** Deterministic keyed hash: same input -> same output, so joins still work, but not reversible. */
public class HashAction implements Action {
    private final Hmac hmac;
    public HashAction(Hmac hmac) { this.hmac = hmac; }

    @Override public ActionType type() { return ActionType.HASH; }

    @Override public String apply(Finding f) {
        return "HASH_" + hmac.hex(f.type().name() + ":" + f.value()).substring(0, 24);
    }
}
