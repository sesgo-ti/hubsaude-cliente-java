/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

package br.gov.go.saude.hubsaude.client.archrules;

import java.util.List;

import com.tngtech.archunit.base.ArchUnitException.ReflectionException;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaModifier;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import com.tngtech.archunit.lang.syntax.ArchRuleDefinition;
import com.tngtech.archunit.library.GeneralCodingRules;
import com.tngtech.archunit.library.dependencies.SlicesRuleDefinition;
import com.tngtech.archunit.library.freeze.FreezingArchRule;

/**
 * Conjunto de <i>fitness functions</i> ArchUnit aplicadas a este
 * cliente Java. As regras encapsulam decisões arquiteturais (ADR-15
 * — modularização hexagonal; ADR-70 — domínio fechado por padrão) e
 * convenções operacionais (logging via SLF4J, ausência de ciclos
 * entre subpacotes, Loggers como {@code private static final}).
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

    /**
     * Regra (e): classes públicas de {@code **.domain..} são
     * <strong>fechadas por padrão</strong> — {@code final},
     * {@code sealed}, {@code abstract}, {@code record} ou
     * {@code enum} (ADR-70, REC-26); interfaces e anotações são
     * contratos permitidos. Extensibilidade é opt-in.
     *
     * <p>Entregue via {@link FreezingArchRule}: violações existentes
     * ao primeiro run viram baseline em
     * {@code src/test/resources/archunit_store/}; novas violações
     * falham o build.
     */
    public static ArchRule domainClassesAreClosedByDefault(
            String basePackage) {
        return FreezingArchRule.freeze(ArchRuleDefinition
                .classes()
                .that().resideInAPackage(basePackage + "..domain..")
                .and().arePublic()
                .should(serFechadaPorPadrao())
                .as("Classes públicas em '" + basePackage
                        + "..domain..' devem ser fechadas por padrão — "
                        + "final, sealed, abstract, record ou enum; "
                        + "interfaces e anotações são contratos "
                        + "permitidos. Extensibilidade é opt-in "
                        + "(ADR-70, REC-26).")
                .allowEmptyShould(true));
    }

    /**
     * Condição: a classe é fechada por padrão — interface/anotação
     * (contrato), {@code enum}, {@code record}, {@code abstract},
     * {@code final} ou {@code sealed}.
     */
    private static ArchCondition<JavaClass> serFechadaPorPadrao() {
        return new ArchCondition<>("ser fechada por padrão (final, "
                + "sealed, abstract, record, enum ou interface)") {
            @Override
            public void check(JavaClass classe, ConditionEvents events) {
                if (!ehFechadaPorPadrao(classe)) {
                    events.add(SimpleConditionEvent.violated(
                            classe,
                            String.format(
                                    "%s é pública, concreta e aberta "
                                            + "(nem final nem sealed) "
                                            + "em %s",
                                    classe.getDescription(),
                                    classe.getSourceCodeLocation())));
                }
            }
        };
    }

    /**
     * Indica se a classe é fechada por padrão (ADR-70): contrato
     * (interface — inclui anotações, que têm {@code ACC_INTERFACE}
     * no bytecode), {@code enum}, {@code record}, {@code abstract},
     * {@code final} ou {@code sealed}.
     */
    private static boolean ehFechadaPorPadrao(JavaClass classe) {
        return classe.isInterface()
                || classe.isEnum()
                || classe.isRecord()
                || classe.getModifiers().contains(JavaModifier.FINAL)
                || classe.getModifiers().contains(JavaModifier.ABSTRACT)
                || ehSealed(classe);
    }

    /**
     * Detecta {@code sealed} via reflexão: o ArchUnit não expõe o
     * modificador em {@link JavaModifier} e {@code sealed} não gera
     * flag no bytecode (apenas o atributo
     * {@code PermittedSubclasses}). As classes analisadas estão no
     * classpath de teste do próprio cliente, logo {@code reflect()}
     * resolve. Se a classe não for resolvível, assume-se
     * <em>não-sealed</em> (conservador: a violação vai para a
     * linha-base congelada em vez de passar em silêncio).
     */
    private static boolean ehSealed(JavaClass classe) {
        try {
            return classe.reflect().isSealed();
        } catch (ReflectionException e) {
            return false;
        }
    }
}
