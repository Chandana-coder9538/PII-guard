package com.piiguard.engine;

/** Metadata only. The raw value is NEVER stored, just a short keyed fingerprint. */
public record AuditRecord(int row, String column, String piiType, String action, String fingerprint) {}
