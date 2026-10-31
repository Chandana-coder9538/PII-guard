package com.piiguard;

import com.piiguard.detect.*;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class DetectorTest {
    private final DetectorRegistry reg = new DetectorRegistry();

    @Test void aadhaarNeedsValidChecksum() {
        String good = VerhoeffValidator.withCheckDigit("23456789012");
        String bad = good.substring(0, 11) + ((good.charAt(11) - '0' + 1) % 10);
        assertEquals(1, reg.detect(PiiType.AADHAAR, "id " + good).size());
        assertEquals(0, reg.detect(PiiType.AADHAAR, "id " + bad).size());
    }

    @Test void phoneVariants() {
        assertEquals(1, reg.detect(PiiType.PHONE, "call 9876543210").size());
        assertEquals(1, reg.detect(PiiType.PHONE, "call +91 98765 43210").size());
        assertEquals(0, reg.detect(PiiType.PHONE, "order 1234567890").size());
    }

    @Test void cardNeedsLuhn() {
        assertEquals(1, reg.detect(PiiType.CARD, "4111 1111 1111 1111").size());
        assertEquals(0, reg.detect(PiiType.CARD, "4111 1111 1111 1112").size());
    }

    @Test void panEmailIfscIp() {
        assertEquals(1, reg.detect(PiiType.PAN, "ABCDE1234F").size());
        assertEquals(1, reg.detect(PiiType.EMAIL, "a.b@x.co.in").size());
        assertEquals(1, reg.detect(PiiType.IFSC, "SBIN0001234").size());
        assertEquals(1, reg.detect(PiiType.IPV4, "from 192.168.1.10 ok").size());
        assertEquals(0, reg.detect(PiiType.IPV4, "version 1.2.3.999").size());
    }
}
