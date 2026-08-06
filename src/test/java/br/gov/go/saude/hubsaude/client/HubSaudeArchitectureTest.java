/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.hubsaude.client;

import org.junit.jupiter.api.Test;

import com.tngtech.archunit.core.domain.JavaClasses;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;

import br.gov.go.saude.hubsaude.client.archrules.ClientArchRules;

/**
 * Aplica as <i>fitness functions</i> ArchUnit deste cliente
 * (ver {@link ClientArchRules}) sobre as classes do módulo.
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
        ClientArchRules.domainHasNoForbiddenDependencies(BASE_PACKAGE)
                .check(classes);
    }

    @Test
    void semCiclosEntreSubpacotes() {
        ClientArchRules.noCyclicDependenciesBetweenSlices(BASE_PACKAGE)
                .check(classes);
    }

    @Test
    void semSystemOutOuErr() {
        ClientArchRules.noUseOfStandardStreams().check(classes);
    }

    @Test
    void loggersSaoPrivateStaticFinal() {
        ClientArchRules.loggersArePrivateStaticFinal().check(classes);
    }

    @Test
    void dominioFechadoPorPadrao() {
        ClientArchRules.domainClassesAreClosedByDefault(BASE_PACKAGE)
                .check(classes);
    }
}
