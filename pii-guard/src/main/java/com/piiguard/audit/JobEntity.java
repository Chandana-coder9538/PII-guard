package com.piiguard.audit;

import jakarta.persistence.*;
import java.time.Instant;

@Entity
@Table(name = "job")
public class JobEntity {
    @Id private String id;
    private String fileName;
    private String recipeName;
    private String status;
    private int rowsTotal;
    private int rowsWithPii;
    private int findingsTotal;
    private int residualFindings;
    private String outputSha256;
    private String outputPath;
    private Instant createdAt = Instant.now();
    private long durationMs;

    protected JobEntity() {}
    public JobEntity(String id) { this.id = id; }

    public String getId() { return id; }
    public String getFileName() { return fileName; }
    public void setFileName(String v) { fileName = v; }
    public String getRecipeName() { return recipeName; }
    public void setRecipeName(String v) { recipeName = v; }
    public String getStatus() { return status; }
    public void setStatus(String v) { status = v; }
    public int getRowsTotal() { return rowsTotal; }
    public void setRowsTotal(int v) { rowsTotal = v; }
    public int getRowsWithPii() { return rowsWithPii; }
    public void setRowsWithPii(int v) { rowsWithPii = v; }
    public int getFindingsTotal() { return findingsTotal; }
    public void setFindingsTotal(int v) { findingsTotal = v; }
    public int getResidualFindings() { return residualFindings; }
    public void setResidualFindings(int v) { residualFindings = v; }
    public String getOutputSha256() { return outputSha256; }
    public void setOutputSha256(String v) { outputSha256 = v; }
    public String getOutputPath() { return outputPath; }
    public void setOutputPath(String v) { outputPath = v; }
    public Instant getCreatedAt() { return createdAt; }
    public long getDurationMs() { return durationMs; }
    public void setDurationMs(long v) { durationMs = v; }
}
