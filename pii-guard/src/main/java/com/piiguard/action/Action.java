package com.piiguard.action;

import com.piiguard.detect.Finding;

public interface Action {
    ActionType type();
    String apply(Finding f);
}
