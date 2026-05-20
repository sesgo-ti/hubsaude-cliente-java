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
 *
 * A menos que exigido por lei aplicável ou acordado por escrito,
 * o software distribuído sob a Licença é distribuído "NO ESTADO
 * EM QUE SE ENCONTRA", SEM GARANTIAS OU CONDIÇÕES DE QUALQUER
 * TIPO, expressas ou implícitas. Consulte a Licença para o
 * idioma específico que rege permissões e limitações sob a
 * Licença.
 */

package br.gov.go.saude.hubsaude.client;

/**
 * Exceção de domínio para operações utilitárias do {@link SmartTokenClient}.
 *
 * <p>
 * Sinaliza falhas de parsing de PEM/JSON ou respostas inesperadas do
 * servidor de autorização, preservando a causa original para facilitar o diagnóstico.
 * </p>
 */
public class SmartTokenException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Cria a exceção apenas com a mensagem.
     *
     * @param message descrição da falha
     */
    public SmartTokenException(final String message) {
        super(message);
    }

    /**
     * Cria a exceção preservando a causa original.
     *
     * @param message descrição da falha
     * @param cause   exceção original que motivou esta
     */
    public SmartTokenException(final String message, final Throwable cause) {
        super(message, cause);
    }
}
