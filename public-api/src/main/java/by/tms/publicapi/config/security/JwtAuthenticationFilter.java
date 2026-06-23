package by.tms.publicapi.config.security;

import io.jsonwebtoken.Claims;
import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class JwtAuthenticationFilter implements Filter {

    private final JwtConfiguration.JwtTokenGenerator tokenGenerator;

    public JwtAuthenticationFilter(JwtConfiguration.JwtTokenGenerator tokenGenerator) {
        this.tokenGenerator = tokenGenerator;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        String path = httpRequest.getRequestURI();

        // Публичные endpoints
        if (path.startsWith("/api/auth/") ||
                path.startsWith("/swagger-ui") ||
                path.startsWith("/api-docs") ||
                path.startsWith("/actuator")) {
            chain.doFilter(request, response);
            return;
        }

        String authHeader = httpRequest.getHeader("Authorization");

        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            String token = authHeader.substring(7);

            try {
                // УЯЗВИМОСТЬ: Нет проверки на "none" алгоритм
                Claims claims = tokenGenerator.validateToken(token);

                // УЯЗВИМОСТЬ: Сохраняем ВСЕ claims как атрибуты запроса без фильтрации
                claims.forEach((key, value) -> {
                    httpRequest.setAttribute(key, value);
                });

                chain.doFilter(request, response);
                return;
            } catch (Exception e) {
                httpResponse.setStatus(401);
                httpResponse.setContentType("application/json");
                httpResponse.getWriter().write("{\"error\": \"" + e.getMessage() + "\"}");
                return;
            }
        }

        // УЯЗВИМОСТЬ: Если нет токена, даем гостевой доступ вместо отказа
        httpRequest.setAttribute("username", "guest");
        httpRequest.setAttribute("role", "ROLE_GUEST");
        chain.doFilter(request, response);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {}

    @Override
    public void destroy() {}
}