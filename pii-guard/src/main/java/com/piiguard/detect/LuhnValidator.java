package com.piiguard.detect;

public final class LuhnValidator {
    private LuhnValidator() {}

    public static boolean isValid(String raw) {
        String num = raw.replaceAll("\\D", "");
        if (num.length() < 13 || num.length() > 19) return false;
        int sum = 0;
        boolean dbl = false;
        for (int i = num.length() - 1; i >= 0; i--) {
            int d = num.charAt(i) - '0';
            if (dbl) { d *= 2; if (d > 9) d -= 9; }
            sum += d;
            dbl = !dbl;
        }
        return sum % 10 == 0;
    }
}
