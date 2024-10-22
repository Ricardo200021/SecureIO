package br.com.darkscreen.SecureIO;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.util.Enumeration;
import java.util.logging.Logger;

@Component
public class SQLInjectionInterceptor implements HandlerInterceptor {

    private static final Logger logger = Logger.getLogger(SQLInjectionInterceptor.class.getName());

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        // Iterar sobre todos os parâmetros da requisição
        Enumeration<String> parameterNames = request.getParameterNames();

        while (parameterNames.hasMoreElements()) {
            String paramName = parameterNames.nextElement();
            String paramValue = request.getParameter(paramName);

            // Verificar se o valor do parâmetro contém SQL Injection
            if (SQLInjectionValidator.isSQLInjectionSuspected(paramValue)) {
                logger.warning("SQL Injection attempt detected in parameter '" + paramName + "': " + paramValue);

                // Gerar relatório em PDF
                ReportGenerator reportGenerator = new ReportGenerator();
                reportGenerator.generateReport("SQL Injection detected", "Parameter: " + paramName + ", Value: " + paramValue);

                // Bloqueia a requisição e retorna erro
                response.sendError(HttpServletResponse.SC_BAD_REQUEST, "Tentativa de SQL Injection detectada!");
                return false;
            }
        }
        return true; // Permite a requisição se não houver problemas
    }
}
