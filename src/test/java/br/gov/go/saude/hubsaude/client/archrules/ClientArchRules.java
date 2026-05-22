/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás — Secretaria de Estado da Saúde (SES-GO).
 * Copyright 2025-2026 Universidade Federal de Goiás (UFG) —
 *     Instituto de Informática / Fábrica de Software.
 *
 * Licenciado sob a Apache License, Version 2.0 (a "Licença");
 * você só pode usar este arquivo em conformidade com a Licença.
 * Você pode obter uma cópia da Licença em
 *
 *     https://www.apache.org/licenses/LICENSE-2.0
 */

package br.gov.go.saude.hubsaude.client.archrules;

import java.util.List;

import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition;
import com.tngtech.archunit.library.GeneralCodingRules;
import com.tngtech.archunit.library.dependencies.SlicesRuleDefinition;
import com.tngtech.archunit.library.freeze.FreezingArchRule;

/**
 * Conjunto de <i>fitness functions</i> ArchUnit aplicadas a este
 * cliente Java. As regras encapsulam decisões arquiteturais (ADR-15
 * — modularização hexagonal) e convenções operacionais (logging via
 * SLF4J, ausência de ciclos entre subpacotes, Loggers como
 * {@code private static final}).
 *
 * <p>Replicado localmente para que o artefato publicado em Maven
 * Central não tenha dependência (nem mesmo transitória de teste) do
 * monorepo HubSaúde — preservando a independência exigida pelo
 * consumo externo do cliente.
 *
 * <p>Bibliotecas vetadas dentro de {@code **.domain..}:
 * Spring Framework, Jackson, JDBC, Kafka, JGit, HAPI FHIR e
 * Hibernate. O domínio deve ser puro Java SE; integrações pertencem
 * a adaptadores em {@code **.infrastructure..} ou pacotes de borda.
 */
public final class ClientArchRules {

    /** Pacotes considerados infraestrutura externa proibida no domínio. */
    private static final List<String> FORBIDDEN_IN_DOMAIN = List.of(
            "org.springframework..",
            "com.fasterxml.jackson..",
            "java.sql..",
            "javax.sql..",
            "org.apache.kafka..",
            "org.springframework.kafka..",
            "org.eclipse.jgit..",
            "ca.uhn.hapi.fhir..",
            "org.hibernate.."
    );

    private ClientArchRules() {}

    /**
     * Regra (a): classes em {@code **.domain..} não dependem de
     * Spring/Jackson/JDBC/Kafka/JGit/HAPI FHIR/Hibernate.
     */
    public static ArchRule domainHasNoForbiddenDependencies(
            String basePackage) {
        return ArchRuleDefinition
                .noClasses()
                .that().resideInAPackage(basePackage + "..domain..")
                .should().dependOnClassesThat()
                .resideInAnyPackage(
                        FORBIDDEN_IN_DOMAIN.toArray(new String[0]))
                .as("Classes em '" + basePackage
                        + "..domain..' não devem depender de frameworks "
                        + "de infraestrutura (Spring, Jackson, JDBC, "
                        + "Kafka, JGit, HAPI FHIR, Hibernate). "
                        + "ADR-15 — modularização hexagonal.")
                .allowEmptyShould(true);
    }

    /**
     * Regra (b): sem ciclos entre subpacotes diretos do serviço.
     */
    public static ArchRule noCyclicDependenciesBetweenSlices(
            String basePackage) {
        return FreezingArchRule.freeze(SlicesRuleDefinition
                .slices()
                .matching(basePackage + ".(*)..")
                .should().beFreeOfCycles()
                .as("Subpacotes de '" + basePackage
                        + "' devem ser livres de ciclos.")
                .allowEmptyShould(true));
    }

    /**
     * Regra (c): nenhuma classe usa {@code System.out} ou
     * {@code System.err}; saída de log deve usar SLF4J.
     *
     * <p>Entregue via {@link FreezingArchRule}: violações existentes
     * ao primeiro run viram baseline em
     * {@code src/test/resources/archunit_store/}; novas violações
     * falham o build.
     */
    public static ArchRule noUseOfStandardStreams() {
        return FreezingArchRule.freeze(
                GeneralCodingRules
                        .NO_CLASSES_SHOULD_ACCESS_STANDARD_STREAMS
                        .as("Nenhuma classe deve acessar "
                                + "System.out/System.err; use SLF4J Logger."));
    }

    /**
     * Regra (d): campos do tipo {@code org.slf4j.Logger} devem ser
     * {@code private static final}.
     */
    public static ArchRule loggersArePrivateStaticFinal() {
        return ArchRuleDefinition
                .fields()
                .that().haveRawType("org.slf4j.Logger")
                .should().bePrivate()
                .andShould().beStatic()
                .andShould().beFinal()
                .as("Campos do tipo org.slf4j.Logger devem ser "
                        + "private static final.")
                .allowEmptyShould(true);
    }
}
