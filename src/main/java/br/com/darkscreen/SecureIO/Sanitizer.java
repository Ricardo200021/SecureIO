package br.com.darkscreen.SecureIO;

import org.springframework.stereotype.Component;

import java.util.logging.Logger;

@Component
public class Sanitizer {

    private static final Logger logger = Logger.getLogger(Sanitizer.class.getName());

    public Sanitizer() {
        try {
            // Lógica de inicialização, como carregar a política AntiSamy
            logger.info("Sanitizer initialized successfully.");
        } catch (Exception e) {
            // Logar o erro
            logger.severe("Error initializing Sanitizer: " + e.getMessage());
            throw new RuntimeException("Erro ao inicializar Sanitizer", e);
        }
    }

    public String sanitize(String input) {
        if (input == null || input.trim().isEmpty()) {
            return ""; // Retorna string vazia se a entrada for nula ou vazia
        }

        // Exemplo de sanitização básica para prevenir XSS e SQL Injection
        String sanitizedInput = input.replaceAll("<", "&lt;")  // Converte "<" para "&lt;"
                .replaceAll(">", "&gt;") // Converte ">" para "&gt;"
                .replaceAll("&", "&amp;") // Converte "&" para "&amp;"
                .replaceAll("'", "&#39;") // Converte "'" para "&#39;"
                .replaceAll("\"", "&quot;"); // Converte '"' para "&quot;"

        logger.info("Input sanitized: " + sanitizedInput); // Loga a entrada sanitizada
        return sanitizedInput; // Retorna a entrada sanitizada
    }
}
