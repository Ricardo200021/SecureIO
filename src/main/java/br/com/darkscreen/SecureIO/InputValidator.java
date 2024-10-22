package br.com.darkscreen.SecureIO;

import java.util.Map;
import java.util.logging.Logger;
import java.util.regex.Pattern;

public class InputValidator {

    // Logger para registrar tentativas suspeitas
    private static final Logger logger = Logger.getLogger(InputValidator.class.getName());

    // Padrões refinados de SQL Injection
    private static final Pattern[] SQL_INJECTION_PATTERNS = {
            Pattern.compile("('.+--)|(--)|(%7C)", Pattern.CASE_INSENSITIVE), // Comentários "--"
            Pattern.compile("'\\s*or\\s+\\d+=\\d+", Pattern.CASE_INSENSITIVE), // Ataques de OR lógicos
            Pattern.compile("union\\s+select", Pattern.CASE_INSENSITIVE), // UNION SELECT para combinação de tabelas
            Pattern.compile("select\\s+.*\\s+from\\s+", Pattern.CASE_INSENSITIVE), // SELECT FROM pattern
            Pattern.compile("insert\\s+into", Pattern.CASE_INSENSITIVE), // INSERT INTO
            Pattern.compile("delete\\s+from", Pattern.CASE_INSENSITIVE), // DELETE FROM
            Pattern.compile("drop\\s+table", Pattern.CASE_INSENSITIVE), // DROP TABLE
            Pattern.compile("update\\s+.*\\s+set\\s+", Pattern.CASE_INSENSITIVE), // UPDATE SET
            Pattern.compile("alter\\s+table", Pattern.CASE_INSENSITIVE) // ALTER TABLE
    };

    // Padrões refinados de XSS
    private static final Pattern[] XSS_PATTERNS = {
            Pattern.compile("<script>(.*?)</script>", Pattern.CASE_INSENSITIVE | Pattern.DOTALL), // Scripts JS
            Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE), // JS URI scheme
            Pattern.compile("onerror=", Pattern.CASE_INSENSITIVE), // Eventos de erro
            Pattern.compile("onload=", Pattern.CASE_INSENSITIVE), // Eventos de carregamento
            Pattern.compile("<.*?>", Pattern.CASE_INSENSITIVE) // Tags HTML completas
    };

    // Método para verificar se a entrada contém padrões de SQL Injection
    public static boolean isSQLInjectionSuspected(String input) {
        if (input == null || input.trim().isEmpty()) {
            return false; // Entrada vazia ou nula não é considerada
        }

        // Verificar padrões perigosos
        for (Pattern pattern : SQL_INJECTION_PATTERNS) {
            if (pattern.matcher(input).find()) {
                logger.warning("SQL Injection attempt detected: " + input);
                return true;
            }
        }
        return false; // Nenhum padrão de SQL Injection encontrado
    }

    // Método para verificar se a entrada contém padrões de XSS
    public static boolean isXSSSuspected(String input) {
        if (input == null || input.trim().isEmpty()) {
            return false; // Entrada vazia ou nula não é considerada
        }

        // Verificar padrões perigosos
        for (Pattern pattern : XSS_PATTERNS) {
            if (pattern.matcher(input).find()) {
                logger.warning("XSS attempt detected: " + input);
                return true;
            }
        }
        return false; // Nenhum padrão de XSS encontrado
    }

    // Método para verificar entradas de formulários (x-www-form-urlencoded) para SQL Injection
    public static boolean isSQLInjectionSuspectedForm(Map<String, String> params) {
        for (String key : params.keySet()) {
            String value = params.get(key);
            if (isSQLInjectionSuspected(value)) {
                return true; // Retorna verdadeiro se detectar SQL Injection
            }
        }
        return false; // Nenhuma SQL Injection detectada nos parâmetros
    }

    // Método para verificar entradas JSON para SQL Injection
    public static boolean isSQLInjectionSuspectedJSON(Map<String, Object> json) {
        for (String key : json.keySet()) {
            Object value = json.get(key);
            if (value instanceof String && isSQLInjectionSuspected((String) value)) {
                return true; // Retorna verdadeiro se detectar SQL Injection
            }
        }
        return false; // Nenhuma SQL Injection detectada no JSON
    }

    // Método para verificar entradas de formulários (x-www-form-urlencoded) para XSS
    public static boolean isXSSSuspectedForm(Map<String, String> params) {
        for (String key : params.keySet()) {
            String value = params.get(key);
            if (isXSSSuspected(value)) {
                return true; // Retorna verdadeiro se detectar XSS
            }
        }
        return false; // Nenhuma XSS detectada nos parâmetros
    }

    // Método para verificar entradas JSON para XSS
    public static boolean isXSSSuspectedJSON(Map<String, Object> json) {
        for (String key : json.keySet()) {
            Object value = json.get(key);
            if (value instanceof String && isXSSSuspected((String) value)) {
                return true; // Retorna verdadeiro se detectar XSS
            }
        }
        return false; // Nenhuma XSS detectada no JSON
    }
}
