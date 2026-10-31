package com.piiguard.config;

import com.piiguard.action.TokenStore;
import com.piiguard.crypto.AesGcm;
import com.piiguard.crypto.Hmac;
import com.piiguard.detect.DetectorRegistry;
import com.piiguard.engine.RecipeEngine;
import com.piiguard.io.FileProcessor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CoreConfig {

    @Bean Hmac hmac(@Value("${piiguard.hmac-secret}") String secret) { return new Hmac(secret); }

    @Bean AesGcm aesGcm(@Value("${piiguard.vault-secret}") String secret) { return new AesGcm(secret); }

    @Bean DetectorRegistry detectorRegistry() { return new DetectorRegistry(); }

    @Bean RecipeEngine recipeEngine(DetectorRegistry r, Hmac h, TokenStore tokens) {
        return new RecipeEngine(r, h, tokens);
    }

    @Bean FileProcessor fileProcessor(RecipeEngine engine) { return new FileProcessor(engine); }
}
