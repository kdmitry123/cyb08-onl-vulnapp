package by.tms.publicapi.config.security;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

@Configuration
public class SecurityConfiguration {

    @Bean
    public FilterRegistrationBean<SimpleWafFilter> wafFilter() {
        FilterRegistrationBean<SimpleWafFilter> registrationBean =
                new FilterRegistrationBean<>();
        registrationBean.setFilter(new SimpleWafFilter());
        registrationBean.addUrlPatterns("/api/*");
        registrationBean.setOrder(Ordered.HIGHEST_PRECEDENCE);
        return registrationBean;
    }

    @Bean
    public FilterRegistrationBean<JwtAuthenticationFilter> jwtFilter(
            JwtConfiguration.JwtTokenGenerator tokenGenerator) {
        FilterRegistrationBean<JwtAuthenticationFilter> registrationBean =
                new FilterRegistrationBean<>();
        registrationBean.setFilter(new JwtAuthenticationFilter(tokenGenerator));
        registrationBean.addUrlPatterns("/api/*");
        registrationBean.setOrder(Ordered.HIGHEST_PRECEDENCE + 1);
        return registrationBean;
    }

}
