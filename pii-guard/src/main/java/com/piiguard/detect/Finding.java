package com.piiguard.detect;

public record Finding(PiiType type, int start, int end, String value) {
    public int length() { return end - start; }
}
