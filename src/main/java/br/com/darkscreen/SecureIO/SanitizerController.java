package br.com.darkscreen.SecureIO;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.logging.Logger;

@RestController
@RequestMapping("/sanitize")
public class SanitizerController {

    private final Sanitizer sanitizer;
    private static final Logger logger = Logger.getLogger(SanitizerController.class.getName());

    @Autowired
    public SanitizerController(Sanitizer sanitizer) {
        this.sanitizer = sanitizer;
    }

    @PostMapping("/")
    public ResponseEntity<String> sanitize(@RequestBody String input) {
        // Verifica se a entrada é suspeita de SQL Injection
        if (SQLInjectionValidator.isSQLInjectionSuspected(input)) {
            logger.warning("SQL Injection attempt detected: " + input);
            return ResponseEntity.badRequest().body("SQL Injection attempt detected: " + input);
        }

        // Verifica se a entrada é suspeita de XSS
        if (XssValidator.isXSSSuspected(input)) {
            logger.warning("XSS attempt detected: " + input);
            return ResponseEntity.badRequest().body("XSS attempt detected: " + input);
        }

        // Se a entrada for segura, sanitiza e retorna o resultado
        String sanitizedInput = sanitizer.sanitize(input);
        return ResponseEntity.ok("Input sanitized: " + sanitizedInput);
    }
}
