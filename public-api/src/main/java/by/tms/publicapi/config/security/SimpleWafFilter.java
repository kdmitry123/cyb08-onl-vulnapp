package by.tms.publicapi.config.security;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@Component
public class SimpleWafFilter implements Filter {

    // Только базовые ключевые слова
    private static final List<String> BLOCKED_KEYWORDS = Arrays.asList(
            "union select", "1=1", "1=2", "' or '", "' and '",
            "or 1=1", "and 1=1", "or '1'='1", "and '1'='1"
    );

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // УЯЗВИМОСТЬ: Bypass через X-Forwarded-For
        String bypassHeader = httpRequest.getHeader("X-Forwarded-For");
        if (bypassHeader != null && bypassHeader.equals("127.0.0.1")) {
            chain.doFilter(request, response);
            return;
        }

        // УЯЗВИМОСТЬ: Bypass через X-Original-URL
        String originalUrl = httpRequest.getHeader("X-Original-URL");
        if (originalUrl != null && originalUrl.contains("internal")) {
            chain.doFilter(request, response);
            return;
        }

        // УЯЗВИМОСТЬ: Проверяем только GET запросы
        String queryString = httpRequest.getQueryString();
        if (queryString != null && "GET".equalsIgnoreCase(httpRequest.getMethod())) {

            // Декодируем URL
            String decodedQuery;
            try {
                decodedQuery = java.net.URLDecoder.decode(queryString, "UTF-8");
            } catch (Exception e) {
                decodedQuery = queryString;
            }

            // УЯЗВИМОСТЬ: Проверяем только точные совпадения в нижнем регистре
            String lowerQuery = decodedQuery.toLowerCase();

            for (String keyword : BLOCKED_KEYWORDS) {
                if (lowerQuery.contains(keyword)) {
                    httpResponse.setStatus(403);
                    httpResponse.setContentType("application/json");
                    httpResponse.getWriter().write(
                            String.format(
                                    "{\"error\":\"Request blocked by WAF\",\"keyword\":\"%s\"}",
                                    keyword
                            )
                    );
                    return;
                }
            }
        }

        // УЯЗВИМОСТЬ: Пропускаем все POST запросы
        if ("POST".equalsIgnoreCase(httpRequest.getMethod()) ||
                "PUT".equalsIgnoreCase(httpRequest.getMethod())) {
            chain.doFilter(request, response);
            return;
        }

        chain.doFilter(request, response);
    }

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {}

    @Override
    public void destroy() {}
}