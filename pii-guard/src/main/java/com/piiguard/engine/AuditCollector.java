package com.piiguard.engine;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

public class AuditCollector {
    private final List<AuditRecord> records = new ArrayList<>();
    private int residual = 0;

    public void record(AuditRecord r) { records.add(r); }
    public void addResidual(int n) { residual += n; }

    public List<AuditRecord> records() { return records; }
    public int residualFindings() { return residual; }
    public int total() { return records.size(); }

    /** "AADHAAR/TOKENIZE" -> count */
    public Map<String, Integer> summary() {
        Map<String, Integer> m = new TreeMap<>();
        for (AuditRecord r : records) m.merge(r.piiType() + "/" + r.action(), 1, Integer::sum);
        return m;
    }
}
