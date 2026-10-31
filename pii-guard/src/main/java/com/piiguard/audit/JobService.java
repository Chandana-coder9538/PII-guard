package com.piiguard.audit;

import com.piiguard.engine.AuditCollector;
import com.piiguard.engine.Recipe;
import com.piiguard.io.FileProcessor;
import com.piiguard.io.ProcessStats;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.List;
import java.util.UUID;

@Service
public class JobService {
    private final FileProcessor processor;
    private final JobRepository jobs;
    private final AuditEventRepository events;
    private final Path baseDir;

    public JobService(FileProcessor processor, JobRepository jobs, AuditEventRepository events,
                      @Value("${piiguard.output-dir}") String outputDir) throws IOException {
        this.processor = processor; this.jobs = jobs; this.events = events;
        this.baseDir = Path.of(outputDir);
        Files.createDirectories(baseDir);
    }

    public JobEntity run(String fileName, InputStream in, Recipe recipe) throws Exception {
        long t0 = System.currentTimeMillis();
        String id = UUID.randomUUID().toString();
        Path out = baseDir.resolve(id + "-masked" + (isCsv(fileName) ? ".csv" : ".txt"));
        AuditCollector audit = new AuditCollector();
        ProcessStats stats;
        try (OutputStream os = Files.newOutputStream(out)) {
            stats = isCsv(fileName) ? processor.processCsv(in, os, recipe, audit)
                                    : processor.processLines(in, os, recipe, audit);
        }
        JobEntity job = new JobEntity(id);
        job.setFileName(fileName);
        job.setRecipeName(recipe.name());
        job.setStatus(audit.residualFindings() == 0 ? "CLEAN" : "RESIDUAL_PII_FOUND");
        job.setRowsTotal(stats.rowsTotal());
        job.setRowsWithPii(stats.rowsWithPii());
        job.setFindingsTotal(audit.total());
        job.setResidualFindings(audit.residualFindings());
        job.setOutputPath(out.toString());
        job.setOutputSha256(sha256(out));
        job.setDurationMs(System.currentTimeMillis() - t0);
        jobs.save(job);
        events.saveAll(audit.records().stream().map(r ->
            new AuditEvent(id, r.row(), r.column(), r.piiType(), r.action(), r.fingerprint())).toList());
        return job;
    }

    public List<AuditEvent> auditFor(String jobId) { return events.findByJobId(jobId); }

    private static boolean isCsv(String name) { return name != null && name.toLowerCase().endsWith(".csv"); }

    private static String sha256(Path p) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        try (InputStream is = Files.newInputStream(p)) {
            byte[] buf = new byte[8192]; int n;
            while ((n = is.read(buf)) > 0) md.update(buf, 0, n);
        }
        return HexFormat.of().formatHex(md.digest());
    }
}
