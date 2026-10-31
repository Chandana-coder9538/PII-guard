package com.piiguard.io;

import com.piiguard.engine.AuditCollector;
import com.piiguard.engine.Recipe;
import com.piiguard.engine.RecipeEngine;
import org.apache.commons.csv.CSVFormat;
import org.apache.commons.csv.CSVParser;
import org.apache.commons.csv.CSVPrinter;
import org.apache.commons.csv.CSVRecord;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/** Streaming processors: one row / one line at a time, never the whole file in memory. */
public class FileProcessor {
    private final RecipeEngine engine;

    public FileProcessor(RecipeEngine engine) { this.engine = engine; }

    public ProcessStats processCsv(InputStream in, OutputStream out, Recipe recipe, AuditCollector audit) throws IOException {
        int rows = 0, withPii = 0;
        try (Reader r = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
             CSVParser parser = CSVFormat.DEFAULT.builder().setHeader().setSkipHeaderRecord(true)
                 .setIgnoreEmptyLines(true).build().parse(r);
             Writer w = new BufferedWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8));
             CSVPrinter printer = new CSVPrinter(w, CSVFormat.DEFAULT)) {

            List<String> headers = parser.getHeaderNames();
            printer.printRecord(headers);
            for (CSVRecord rec : parser) {
                rows++;
                int before = audit.total();
                List<String> cells = new ArrayList<>(headers.size());
                for (String h : headers) {
                    String v = rec.isMapped(h) && rec.isSet(h) ? rec.get(h) : "";
                    cells.add(engine.process(v, recipe, h, rows, audit));
                }
                if (audit.total() > before) withPii++;
                printer.printRecord(cells);
            }
        }
        return new ProcessStats(rows, withPii);
    }

    public ProcessStats processLines(InputStream in, OutputStream out, Recipe recipe, AuditCollector audit) throws IOException {
        int rows = 0, withPii = 0;
        try (BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
             Writer w = new BufferedWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                rows++;
                int before = audit.total();
                w.write(engine.process(line, recipe, null, rows, audit));
                w.write('\n');
                if (audit.total() > before) withPii++;
            }
        }
        return new ProcessStats(rows, withPii);
    }
}
