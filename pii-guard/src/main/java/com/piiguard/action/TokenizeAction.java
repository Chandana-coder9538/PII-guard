package com.piiguard.action;

import com.piiguard.detect.Finding;

public class TokenizeAction implements Action {
    private final TokenStore store;
    public TokenizeAction(TokenStore store) { this.store = store; }

    @Override public ActionType type() { return ActionType.TOKENIZE; }
    @Override public String apply(Finding f) { return store.tokenFor(f.type(), f.value()); }
}
