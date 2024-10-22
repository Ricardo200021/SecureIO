package br.com.darkscreen.SecureIO.config;

import br.com.darkscreen.SecureIO.SQLInjectionInterceptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {

    @Autowired
    private SQLInjectionInterceptor sqlInjectionInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        // Adiciona o interceptor para todas as requisições
        registry.addInterceptor(sqlInjectionInterceptor).addPathPatterns("/sanitize/**", "/api/**"); // Ajuste os paths conforme necessário
    }
}
