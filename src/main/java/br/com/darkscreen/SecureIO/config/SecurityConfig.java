package br.com.darkscreen.SecureIO.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorize -> authorize
                        .requestMatchers("/sanitize/**").permitAll() // Permite acesso ao endpoint de sanitização
                        .requestMatchers("/api/**").authenticated() // Protege as rotas da API que requerem autenticação
                        .anyRequest().permitAll() // Permite acesso a todas as outras rotas
                )
                .httpBasic(withDefaults()) // Usar autenticação básica para a proteção
                .csrf().disable(); // Desativa CSRF para APIs públicas; avalie a necessidade em produção

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(); // Usando BCrypt para codificação de senhas
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new InMemoryUserDetailsManager(
                User.withUsername("user") // Usuário padrão
                        .password(passwordEncoder().encode("password")) // Senha codificada
                        .roles("USER") // Atribui papel de usuário
                        .build()
        );
    }
}
