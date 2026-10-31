package com.piiguard.action;

import com.piiguard.detect.Finding;

/** Type-aware partial masking: keeps just enough to be recognisable by a human. */
public class MaskAction implements Action {
    @Override public ActionType type() { return ActionType.MASK; }

    @Override public String apply(Finding f) {
        String v = f.value();
        switch (f.type()) {
            case EMAIL: {
                int at = v.indexOf('@');
                return v.charAt(0) + "***" + v.substring(at);
            }
            case AADHAAR: return "XXXX XXXX " + lastDigits(v, 4);
            case PHONE:   return "XXXXXX" + lastDigits(v, 4);
            case CARD:    return "XXXX-XXXX-XXXX-" + lastDigits(v, 4);
            case CUSTOM: return v.replaceAll("[\\p{L}\\p{N}]", "X");
            case NAME: {
                StringBuilder sb = new StringBuilder();
                for (String w : v.trim().split("\\s+")) {
                    if (sb.length() > 0) sb.append(' ');
                    sb.append(w.charAt(0)).append("*".repeat(Math.max(2, w.length() - 1)));
                }
                return sb.toString();
            }
            default: {
                int keep = Math.min(4, v.length() / 3);
                StringBuilder sb = new StringBuilder();
                for (int i = 0; i < v.length(); i++) {
                    char ch = v.charAt(i);
                    boolean keepIt = i >= v.length() - keep || !Character.isLetterOrDigit(ch);
                    sb.append(keepIt ? ch : 'X');
                }
                return sb.toString();
            }
        }
    }

    private static String lastDigits(String v, int n) {
        String d = v.replaceAll("\\D", "");
        return d.substring(Math.max(0, d.length() - n));
    }
}