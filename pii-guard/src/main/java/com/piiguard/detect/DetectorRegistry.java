package com.piiguard.detect;

import java.util.*;

/** All regex detectors, keyed by PII type. NAME has no regex: it is column-driven. */
public class DetectorRegistry {
    private final Map<PiiType, Detector> detectors = new EnumMap<>(PiiType.class);

    public DetectorRegistry() {
        add(new RegexDetector(PiiType.AADHAAR,
            "(?<!\\d)[2-9]\\d{3}[ -]?\\d{4}[ -]?\\d{4}(?!\\d)", VerhoeffValidator::isValid));
        add(new RegexDetector(PiiType.PHONE,
            "(?<!\\d)(?:\\+91[\\- ]?|0)?[6-9]\\d{4}[ -]?\\d{5}(?!\\d)", v -> true));
        add(new RegexDetector(PiiType.EMAIL,
            "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}", v -> true));
        add(new RegexDetector(PiiType.PAN,
            "(?<![A-Z0-9])[A-Z]{5}\\d{4}[A-Z](?![A-Z0-9])", v -> true));
        add(new RegexDetector(PiiType.IFSC,
            "(?<![A-Z0-9])[A-Z]{4}0[A-Z0-9]{6}(?![A-Z0-9])", v -> true));
        add(new RegexDetector(PiiType.CARD,
            "(?<!\\d)(?:\\d[ -]?){12,18}\\d(?!\\d)", LuhnValidator::isValid));
        add(new RegexDetector(PiiType.IPV4,
            "(?<![\\d.])(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?![\\d.])",
            v -> true));
    }

    private void add(Detector d) { detectors.put(d.type(), d); }

    public boolean has(PiiType t) { return detectors.containsKey(t); }

    public List<Finding> detect(PiiType t, String text) {
        Detector d = detectors.get(t);
        return d == null ? List.of() : d.detect(text);
    }
}
