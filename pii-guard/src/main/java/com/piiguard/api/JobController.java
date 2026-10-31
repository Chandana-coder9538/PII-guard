package com.piiguard.api;

import com.piiguard.audit.AuditEvent;
import com.piiguard.audit.JobEntity;
import com.piiguard.audit.JobRepository;
import com.piiguard.audit.JobService;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.http.*;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/jobs")
public class JobController {
    private final JobRepository jobs;
    private final JobService service;

    public JobController(JobRepository jobs, JobService service) { this.jobs = jobs; this.service = service; }

    private JobEntity find(String id) {
        return jobs.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND, "job not found"));
    }

    @GetMapping
    public List<JobEntity> list() { return jobs.findAll(); }

    @GetMapping("/{id}")
    public JobEntity get(@PathVariable String id) { return find(id); }

    @GetMapping("/{id}/download")
    public ResponseEntity<Resource> download(@PathVariable String id) {
        JobEntity j = find(id);
        String name = "masked-" + j.getFileName();
        return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"" + name + "\"")
            .contentType(MediaType.APPLICATION_OCTET_STREAM)
            .body(new FileSystemResource(j.getOutputPath()));
    }

    @GetMapping("/{id}/audit")
    public ResponseEntity<?> audit(@PathVariable String id, @RequestParam(defaultValue = "json") String format) {
        JobEntity j = find(id);
        List<AuditEvent> ev = service.auditFor(id);
        if ("csv".equalsIgnoreCase(format)) {
            StringBuilder sb = new StringBuilder("row,column,pii_type,action,fingerprint\n");
            for (AuditEvent e : ev)
                sb.append(e.getRowNumber()).append(',').append(e.getColumnName() == null ? "" : e.getColumnName()).append(',')
                  .append(e.getPiiType()).append(',').append(e.getActionApplied()).append(',')
                  .append(e.getValueFingerprint()).append('\n');
            return ResponseEntity.ok().contentType(MediaType.parseMediaType("text/csv")).body(sb.toString());
        }
        Map<String, Long> counts = new java.util.TreeMap<>();
        for (AuditEvent e : ev) counts.merge(e.getPiiType() + "/" + e.getActionApplied(), 1L, Long::sum);
        return ResponseEntity.ok(Map.of("job", j, "summary", counts, "events", ev));
    }
}
