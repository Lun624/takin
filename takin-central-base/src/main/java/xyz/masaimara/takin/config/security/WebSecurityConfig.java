package xyz.masaimara.takin.config.security;

import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter implements WebMvcConfigurer {

    @Bean
    public static LogoutHandler logoutHandler() {
        SecurityContextLogoutHandler handler = new SecurityContextLogoutHandler() {
            @Override
            public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

            }
        };
        return handler;
    }

    @Bean
    public static LogoutSuccessHandler logoutSuccessHandler() {
        SimpleUrlLogoutSuccessHandler handler = new SimpleUrlLogoutSuccessHandler() {
            @Override
            public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

            }
        };
        return handler;
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
        web.ignoring().antMatchers("/", "/api/**", "/images/**", "/webjars/**",
                "/oauth/uncache_approvals", "/oauth/cache_approvals", "/oauth/authorize", "/oauth/token");
    }

    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        return super.authenticationManagerBean();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
        http.authorizeRequests()
                .antMatchers("/api/**", "/oauth/**").permitAll();
//        http
//                .csrf()
//                .requireCsrfProtectionMatcher(new AntPathRequestMatcher("/oauth/authorize"))
//                .disable()
//                .logout().logoutUrl("/signin")
//                .logoutSuccessUrl("/signin")
//                .and()
//                .formLogin()
//                .loginProcessingUrl("/signin")
//                .failureUrl("/signin?authentication_error=true")
//                .loginPage("/signin");
    }


//    /**
//     * What does it works
//     * <p>
//     * Require authentication to every URL in your application
//     * Generate a login form for you
//     * Allow the user with the Username user and the Password password to authenticate with form based authentication
//     * Allow the user to logout
//     * CSRF attack prevention
//     * Session Fixation protection
//     * Security Header integration
//     * <p>
//     * HTTP Strict Transport Security for secure requests
//     * X-Content-Type-Options integration
//     * Cache Control (can be overridden later by your application to allow caching of your static resources)
//     * X-XSS-Protection integration
//     * X-Frame-Options integration to help prevent Clickjacking
//     * Integrate with the following Servlet API methods
//     * <p>
//     * HttpServletRequest#getRemoteUser()
//     * HttpServletRequest.html#getUserPrincipal()
//     * HttpServletRequest.html#isUserInRole(java.lang.String)
//     * HttpServletRequest.html#login(java.lang.String, java.lang.String)
//     * HttpServletRequest.html#logout()
//     */
////    @Bean
////    public UserDetailsService userDetailsService() {
////        User.UserBuilder users=User.withDefaultPasswordEncoder();
////        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
////        manager.createUser(users.username("user").password("password").roles("USER").build());
////        manager.createUser(users.username("admin").password("password").roles("USER","ADMIN").build());
////        return manager;
////    }
//
//    @Bean
//    public UserDetailsService userDetailsService(@Qualifier("takinDataSource") DataSource dataSource){
//        return new JdbcUserDetailsManager(dataSource);
//    }
//
//    @Bean
//    public BCryptPasswordEncoder bCryptPasswordEncoder(){
//        return new BCryptPasswordEncoder();
//    }
//
//    /**
//     * The default configuration below:
//     *
//     * Ensures that any request to our application requires the user to be authenticated
//     * Allows users to authenticate with form based login
//     * Allows users to authenticate with HTTP Basic authentication
//     */
//
//    /**
//     * 1 Provides logout support. This is automatically applied when using WebSecurityConfigurerAdapter.
//     * 2 The URL that triggers log out to occur (default is /logout). If CSRF protection is enabled (default), then the request must also be a POST. For more information, please consult the JavaDoc.
//     * 3 The URL to redirect to after logout has occurred. The default is /login?logout. For more information, please consult the JavaDoc.
//     * 4 Let’s you specify a custom LogoutSuccessHandler. If this is specified, logoutSuccessUrl() is ignored. For more information, please consult the JavaDoc.
//     * 5 Specify whether to invalidate the HttpSession at the time of logout. This is true by default. Configures the SecurityContextLogoutHandler under the covers. For more information, please consult the JavaDoc.
//     * 6 Adds a LogoutHandler. SecurityContextLogoutHandler is added as the last LogoutHandler by default.
//     * 7 Allows specifying the names of cookies to be removed on logout success. This is a shortcut for adding a CookieClearingLogoutHandler explicitly.
//     */
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
////        super.configure(http);
//        http.authorizeRequests()
//                .antMatchers("/resources/**", "/signup", "/signin", "/about").permitAll()
//                .antMatchers("/admin/**").hasRole("ADMIN")
//                .antMatchers("/db/**").access("hasRole('ADMIN') and hasRole('DBA')")
//                .anyRequest().authenticated()
//                .and()
//                .formLogin()
////                .loginPage("/login")
//                .permitAll()
//                .and()
//                .logout()
//                .logoutUrl("/logout")
//                .logoutSuccessUrl("/index")
//                .logoutSuccessHandler(new LogoutSuccessHandler() {
//                    @Override
//                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//
//                    }
//                })
//                .invalidateHttpSession(true)
//                .addLogoutHandler(new LogoutHandler() {
//                    @Override
//                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//
//                    }
//                });
////        .deleteCookies(new CookieNamesToClear());
//    }
//
//    @Configuration
//    @Order(1)
//    public static class ApiWebSecurityConfigurationAdapter extends WebSecurityConfigurerAdapter {
//
//
//        @Override
//        protected void configure(HttpSecurity http) throws Exception {
//            http
//                    .antMatcher("/api/**")
//                    .authorizeRequests()
//                    .anyRequest().hasRole("ADMIN")
//                    .and()
//                    .httpBasic();
//        }
//    }
//
//    @Configuration
//    @Order(2)
//    public static class OAuth2LoginSecurityConfig extends WebSecurityConfigurerAdapter{
//        @Override
//        protected void configure(HttpSecurity http) throws Exception {
////            http
////                    .oauth2Login()
////                    .clientRegistrationRepository(this.clientRegistrationRepository())
////                    .authorizedClientService(this.authorizedClientService())
////                    .loginPage("/login")
////                    .authorizationEndpoint()
////                    .baseUri(this.authorizationRequestBaseUri())
////                    .authorizationRequestRepository(this.authorizationRequestRepository())
////                    .and()
////                    .redirectionEndpoint()
////                    .baseUri(this.authorizationResponseBaseUri())
////                    .and()
////                    .tokenEndpoint()
////                    .accessTokenResponseClient(this.accessTokenResponseClient())
////                    .and()
////                    .userInfoEndpoint()
////                    .userAuthoritiesMapper(this.userAuthoritiesMapper())
////                    .userService(this.oauth2UserService())
////                    .oidcUserService(this.oidcUserService())
////                    .customUserType(GitHubOAuth2User.class, "github");
//        }
//    }
//
//        @Configuration
//    public static class FormLoginWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
//
//        @Override
//        protected void configure(HttpSecurity http) throws Exception {
//            http.authorizeRequests()
//                    .anyRequest().authenticated()
//                    .and()
//                    .formLogin();
//        }
//}
}
