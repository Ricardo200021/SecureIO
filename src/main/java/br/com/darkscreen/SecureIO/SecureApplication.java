package br.com.darkscreen.SecureIO;

import java.util.regex.Pattern;
import java.util.logging.Logger;

public class SecureApplication {

    private static final Logger logger = Logger.getLogger(SecureApplication.class.getName());

    private static final Pattern[] XSS_PATTERNS = {
            Pattern.compile("<script>(.*?)</script>", Pattern.CASE_INSENSITIVE),
            Pattern.compile("javascript:", Pattern.CASE_INSENSITIVE),
            Pattern.compile("onclick", Pattern.CASE_INSENSITIVE),
            Pattern.compile("onload", Pattern.CASE_INSENSITIVE),
            Pattern.compile("<[^>]+>", Pattern.CASE_INSENSITIVE)
    };

    public static boolean isXSSSuspected(String input) {
        if (input == null || input.trim().isEmpty()) {
            return false;
        }

        for (Pattern pattern : XSS_PATTERNS) {
            if (pattern.matcher(input).find()) {
                logger.warning("XSS pattern detected: " + input);

                // Gerar relatório em PDF
                ReportGenerator reportGenerator = new ReportGenerator();
                reportGenerator.generateReport("XSS Attack Detected", "Suspicious input: " + input);

                return true;
            }
        }
        return false;
    }
}
