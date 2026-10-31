package com.piiguard.detect;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Predicate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Regex candidate finder + optional validator (Verhoeff, Luhn...) to cut false positives. */
public class RegexDetector implements Detector {
    private final PiiType type;
    private final Pattern pattern;
    private final Predicate<String> validator;

    public RegexDetector(PiiType type, String regex, Predicate<String> validator) {
        this.type = type;
        this.pattern = Pattern.compile(regex);
        this.validator = validator;
    }

    @Override public PiiType type() { return type; }

    @Override public List<Finding> detect(String text) {
        List<Finding> out = new ArrayList<>();
        Matcher m = pattern.matcher(text);
        while (m.find()) {
            String v = m.group();
            if (validator.test(v)) out.add(new Finding(type, m.start(), m.end(), v));
        }
        return out;
    }
}
