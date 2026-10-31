package com.piiguard.api;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.piiguard.api.Dtos.*;
import com.piiguard.audit.JobEntity;
import com.piiguard.audit.JobService;
import com.piiguard.detect.PiiType;
import com.piiguard.engine.AuditCollector;
import com.piiguard.engine.Recipe;
import com.piiguard.engine.RecipeEngine;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.EnumSet;
import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class MaskController {
    private final RecipeEngine engine;
    private final JobService jobs;
    private final ObjectMapper mapper;

    public MaskController(RecipeEngine engine, JobService jobs, ObjectMapper mapper) {
        this.engine = engine; this.jobs = jobs; this.mapper = mapper;
    }

    @GetMapping("/recipes/default")
    public Recipe defaultRecipe() { return Recipe.defaultRecipe(); }

    @PostMapping("/mask/text")
    public TextResponse maskText(@RequestBody TextRequest req) {
        Recipe recipe = req.recipe() != null ? req.recipe() : Recipe.defaultRecipe();
        AuditCollector audit = new AuditCollector();
        // text mode processes line by line so row numbers in the audit are meaningful
        StringBuilder sb = new StringBuilder();
        String[] lines = req.text().split("\n", -1);
        for (int i = 0; i < lines.length; i++) {
            if (i > 0) sb.append('\n');
            sb.append(engine.process(lines[i], recipe, null, i + 1, audit));
        }
        return new TextResponse(sb.toString(), audit.summary(), audit.total(), audit.residualFindings());
    }

    @PostMapping("/detect")
    public List<Map<String, Object>> detect(@RequestBody DetectRequest req) {
        return engine.detectOnly(req.text(), EnumSet.complementOf(EnumSet.of(PiiType.NAME)));
    }

    @PostMapping("/mask/file")
    public JobEntity maskFile(@RequestParam("file") MultipartFile file,
                              @RequestParam(value = "recipe", required = false) String recipeJson) throws Exception {
        Recipe recipe = (recipeJson == null || recipeJson.isBlank())
            ? Recipe.defaultRecipe() : mapper.readValue(recipeJson, Recipe.class);
        return jobs.run(file.getOriginalFilename(), file.getInputStream(), recipe);
    }
}
