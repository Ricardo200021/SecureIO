package br.com.darkscreen.SecureIO;

import java.util.regex.Pattern;
import java.util.logging.Logger;

public class XssValidator {

    private static final Logger logger = Logger.getLogger(XssValidator.class.getName());

    // Padrões comuns de XSS
    private static final Pattern[] XSS_PATTERNS = {
            Pattern.compile("<script>(.*?)</script>", Pattern.CASE_INSENSITIVE),
            Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
            Pattern.compile("onclick", Pattern.CASE_INSENSITIVE),
            Pattern.compile("onload", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<[^>]+>", Pattern.CASE_INSENSITIVE) // Captura qualquer tag HTML
    };

    // Método para verificar se a entrada contém padrões de XSS
    public static boolean isXSSSuspected(String input) {
        if (input == null || input.trim().isEmpty()) {
            return false; // Entrada vazia ou nula não é considerada
        }

        // Percorrer todos os padrões e verificar se há algum match
        for (Pattern pattern : XSS_PATTERNS) {
            if (pattern.matcher(input).find()) {
                logger.warning("XSS pattern detected: " + input); // Logando tentativa de XSS

                // Gerar relatório em PDF
                ReportGenerator reportGenerator = new ReportGenerator();
                reportGenerator.generateReport("XSS Attack Detected", "Suspicious input: " + input);

                return true; // Se encontrar algum padrão suspeito, retorna verdadeiro
            }
        }
        return false; // Nenhum padrão suspeito encontrado
    }
}
