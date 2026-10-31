package com.piiguard.vault;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * Re-identification of a whole file: every vault token found in the text is replaced by its original value.
 * Streams line by line. Tokens not in the vault are left untouched. Callers must check the admin key first.
 */
@Service
public class FileRestorer {
    private static final Logger log = LoggerFactory.getLogger(FileRestorer.class);
    private static final Pattern TOKEN = Pattern.compile("TKN_[A-Z0-9]+_[0-9a-f]{12}");

    public record Result(int restored, int unresolved) {}

    private final TokenVault vault;

    public FileRestorer(TokenVault vault) { this.vault = vault; }

    public Result restore(InputStream in, OutputStream out) throws IOException {
        int ok = 0, miss = 0;
        Map<String, Optional<String>> cache = new HashMap<>();
        try (BufferedReader br = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8));
             Writer w = new BufferedWriter(new OutputStreamWriter(out, StandardCharsets.UTF_8))) {
            String line;
            while ((line = br.readLine()) != null) {
                Matcher m = TOKEN.matcher(line);
                StringBuilder sb = new StringBuilder();
                while (m.find()) {
                    String token = m.group();
                    if (cache.size() > 100_000) cache.clear();
                    Optional<String> value = cache.computeIfAbsent(token, vault::detokenize);
                    if (value.isPresent()) ok++; else miss++;
                    m.appendReplacement(sb, Matcher.quoteReplacement(value.orElse(token)));
                }
                m.appendTail(sb);
                w.write(sb.toString());
                w.write('\n');
            }
        }
        log.info("vault.restore restored={} unresolved={}", ok, miss);
        return new Result(ok, miss);
    }
}