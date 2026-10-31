package com.piiguard.audit;

import jakarta.persistence.*;

@Entity
@Table(name = "audit_event", indexes = @Index(name = "ix_audit_job", columnList = "jobId"))
public class AuditEvent {
    @Id @GeneratedValue(strategy = GenerationType.IDENTITY) private Long id;
    private String jobId;
    private int rowNumber;
    private String columnName;
    private String piiType;
    private String actionApplied;
    private String valueFingerprint;

    protected AuditEvent() {}
    public AuditEvent(String jobId, int rowNumber, String columnName, String piiType, String actionApplied, String fp) {
        this.jobId = jobId; this.rowNumber = rowNumber; this.columnName = columnName;
        this.piiType = piiType; this.actionApplied = actionApplied; this.valueFingerprint = fp;
    }
    public String getJobId() { return jobId; }
    public int getRowNumber() { return rowNumber; }
    public String getColumnName() { return columnName; }
    public String getPiiType() { return piiType; }
    public String getActionApplied() { return actionApplied; }
    public String getValueFingerprint() { return valueFingerprint; }
}
