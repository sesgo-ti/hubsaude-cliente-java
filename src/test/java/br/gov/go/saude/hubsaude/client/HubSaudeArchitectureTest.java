/*
 * Copyright (c) 2026 SES-GO / UFG
 * Todos os direitos reservados.
 */

package br.gov.go.saude.hubsaude.client;

import org.junit.jupiter.api.Test;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;

import br.gov.go.saude.hubsaude.archrules.HubSaudeArchRules;

/**
 * Aplica as <i>fitness functions</i> ArchUnit compartilhadas
 * (ver {@link HubSaudeArchRules}) sobre as classes deste serviço.
 *
 * <p>Importa apenas as classes do {@code target/classes} próprio
 * (filtro {@code DoNotIncludeJars} + {@code DoNotIncludeTests}),
 * evitando que classes de dependências disparem violações alheias
 * ao escopo deste módulo.
 */
class HubSaudeArchitectureTest {

    private static final String BASE_PACKAGE = "br.gov.go.saude.hubsaude.client";

    private final JavaClasses classes = new ClassFileImporter()
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_JARS)
            .withImportOption(ImportOption.Predefined.DO_NOT_INCLUDE_TESTS)
            .importPackages(BASE_PACKAGE);

    @Test
    void domainNaoDependeDeFrameworks() {
        HubSaudeArchRules.domainHasNoForbiddenDependencies(BASE_PACKAGE)
                .check(classes);
    }

    @Test
    void semCiclosEntreSubpacotes() {
        HubSaudeArchRules.noCyclicDependenciesBetweenSlices(BASE_PACKAGE)
                .check(classes);
    }

    @Test
    void semSystemOutOuErr() {
        HubSaudeArchRules.noUseOfStandardStreams().check(classes);
    }

    @Test
    void loggersSaoPrivateStaticFinal() {
        HubSaudeArchRules.loggersArePrivateStaticFinal().check(classes);
    }
}
