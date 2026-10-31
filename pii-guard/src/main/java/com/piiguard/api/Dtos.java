package com.piiguard.api;

import com.piiguard.engine.Recipe;

import java.util.Map;

public final class Dtos {
    private Dtos() {}
    public record TextRequest(String text, Recipe recipe) {}
    public record DetectRequest(String text) {}
    public record TextResponse(String masked, Map<String, Integer> summary, int totalFindings, int residualFindings) {}
    public record DetokenizeRequest(String token) {}
}
