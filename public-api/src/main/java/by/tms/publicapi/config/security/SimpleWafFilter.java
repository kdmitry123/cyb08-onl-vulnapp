package by.tms.publicapi.config.security;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.regex.Pattern;

@Component
public class SimpleWafFilter implements Filter {

    private static final List<String> BLOCKED_KEYWORDS = Arrays.asList(
            "union", "select", "insert", "delete", "drop", "exec", "script",
            "../", "etc/passwd", "cmd=", "|", ";", "&&"
    );

    private static final Pattern SQL_INJECTION_PATTERN =
            Pattern.compile("(?i)(\\b(union|select|insert|delete|drop|exec)\\b)");

    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        HttpServletRequest httpRequest = (HttpServletRequest) request;
        HttpServletResponse httpResponse = (HttpServletResponse) response;

        // УЯЗВИМОСТЬ №1: WAF можно обойти через заголовок X-Forwarded-For
        String bypassHeader = httpRequest.getHeader("X-Forwarded-For");
        if (bypassHeader != null && bypassHeader.equals("127.0.0.1")) {
            chain.doFilter(request, response);
            return;
        }

        // УЯЗВИМОСТЬ №2: WAF можно обойти через заголовок X-Original-URL
        String originalUrl = httpRequest.getHeader("X-Original-URL");
        if (originalUrl != null && originalUrl.contains("internal")) {
            chain.doFilter(request, response);
            return;
        }

        // УЯЗВИМОСТЬ №3: Проверяет только query параметры, но не body
        String queryString = httpRequest.getQueryString();
        if (queryString != null) {
            // УЯЗВИМОСТЬ №4: Не проверяет URL-encoded значения
            for (String keyword : BLOCKED_KEYWORDS) {
                if (queryString.toLowerCase().contains(keyword.toLowerCase())) {
                    httpResponse.setStatus(403);
                    httpResponse.setContentType("application/json");
                    httpResponse.getWriter().write(
                            "{\"error\": \"Request blocked by WAF\", \"keyword\": \"" +
                                    keyword + "\"}"
                    );
                    return;
                }
            }
        }

        // УЯЗВИМОСТЬ №5: Пропускает все POST/PUT запросы без проверки body
        if ("POST".equalsIgnoreCase(httpRequest.getMethod()) ||
                "PUT".equalsIgnoreCase(httpRequest.getMethod()) ||
                "DELETE".equalsIgnoreCase(httpRequest.getMethod())) {
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