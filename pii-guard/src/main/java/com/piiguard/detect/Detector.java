package com.piiguard.detect;

import java.util.List;

public interface Detector {
    PiiType type();
    List<Finding> detect(String text);
}
