package br.com.darkscreen.SecureIO;

import java.util.regex.Pattern;
import java.util.logging.Logger;

public class SQLInjectionValidator {

    private static final Logger logger = Logger.getLogger(SQLInjectionValidator.class.getName());
    private static final Pattern[] SQL_INJECTION_PATTERNS = {
            Pattern.compile("'.*?;", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)select.*from", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)insert.*values", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)delete.*from", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)update.*set", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)union.*select", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)drop.*table", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)'.*or.*'.*'.*=", Pattern.CASE_INSENSITIVE),
            Pattern.compile("(?i)--", Pattern.CASE_INSENSITIVE)
    };

    public static boolean isSQLInjectionSuspected(String input) {
        if (input == null || input.trim().isEmpty()) {
            return false;
        }

        for (Pattern pattern : SQL_INJECTION_PATTERNS) {
            if (pattern.matcher(input).find()) {
                logger.warning("SQL Injection attempt detected: " + input);

                // Gerar relatório em PDF
                ReportGenerator reportGenerator = new ReportGenerator();
                reportGenerator.generateReport("SQL Injection Attempt", "Suspicious input: " + input);

                return true;
            }
        }
        return false;
    }
}
