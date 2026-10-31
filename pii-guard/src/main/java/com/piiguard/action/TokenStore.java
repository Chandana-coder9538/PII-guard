package com.piiguard.action;

import com.piiguard.detect.PiiType;

public interface TokenStore {
    /** Returns the existing token for this value, or creates (and stores) a new one. */
    String tokenFor(PiiType type, String value);
}
