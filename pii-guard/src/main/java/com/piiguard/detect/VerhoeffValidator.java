package com.piiguard.detect;

/** Verhoeff checksum, used by Aadhaar numbers. */
public final class VerhoeffValidator {
    private static final int[][] D = {
        {0,1,2,3,4,5,6,7,8,9},{1,2,3,4,0,6,7,8,9,5},{2,3,4,0,1,7,8,9,5,6},
        {3,4,0,1,2,8,9,5,6,7},{4,0,1,2,3,9,5,6,7,8},{5,9,8,7,6,0,4,3,2,1},
        {6,5,9,8,7,1,0,4,3,2},{7,6,5,9,8,2,1,0,4,3},{8,7,6,5,9,3,2,1,0,4},
        {9,8,7,6,5,4,3,2,1,0}};
    private static final int[][] P = {
        {0,1,2,3,4,5,6,7,8,9},{1,5,7,6,2,8,3,0,9,4},{5,8,0,3,7,9,6,1,4,2},
        {8,9,1,6,0,4,3,5,2,7},{9,4,5,3,1,2,6,8,7,0},{4,2,8,6,5,7,3,9,0,1},
        {2,7,9,3,8,0,6,4,1,5},{7,0,4,6,9,1,3,2,5,8}};
    private static final int[] INV = {0,4,3,2,1,5,6,7,8,9};

    private VerhoeffValidator() {}

    public static boolean isValid(String raw) {
        String num = raw.replaceAll("\\D", "");
        if (num.length() != 12) return false;
        int c = 0;
        for (int i = 0; i < num.length(); i++) {
            int digit = num.charAt(num.length() - 1 - i) - '0';
            c = D[c][P[i % 8][digit]];
        }
        return c == 0;
    }

    /** Appends the check digit to an 11-digit base (handy for generating test data). */
    public static String withCheckDigit(String base11) {
        int c = 0;
        for (int i = 0; i < base11.length(); i++) {
            int digit = base11.charAt(base11.length() - 1 - i) - '0';
            c = D[c][P[(i + 1) % 8][digit]];
        }
        return base11 + INV[c];
    }
}
