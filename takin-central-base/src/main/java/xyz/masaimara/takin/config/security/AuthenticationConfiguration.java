package xyz.masaimara.takin.config.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JdbcTokenStore;

import javax.sql.DataSource;

@Configuration
public class AuthenticationConfiguration extends AuthorizationServerConfigurerAdapter {
    @Configuration
    @Order(1)
    @EnableAuthorizationServer
    public static class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {
        @Autowired
        public AuthenticationManager authenticationManager;
        private Logger logger = LoggerFactory.getLogger(AuthorizationServerConfiguration.class);
        private String redirectUri = "/user/account/signin?value=error";
        private BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        @Autowired
        @Qualifier("takinDataSource")
        private DataSource oauth2DataSource;

//        @Bean
//        @Qualifier("takinUserApprovalHandler")
//        public TakinUserApprovalHandler userApprovalHandler(){
//            return new TakinUserApprovalHandler();
//        }

        @Bean
        @Autowired
        public ApprovalStore approvalStore(TokenStore tokenStore) throws Exception {
            TokenApprovalStore store = new TokenApprovalStore();
            store.setTokenStore(tokenStore);
            return store;
        }

        @Bean
        public JdbcTokenStore tokenStore() {
            logger.info("data {}:", null == oauth2DataSource);
            return new JdbcTokenStore(oauth2DataSource);
        }

        protected AuthorizationCodeServices authorizationCodeServices() {
            return new JdbcAuthorizationCodeServices(oauth2DataSource);
        }

        @Bean
        public ClientDetailsService clientDetails() {
            return new JdbcClientDetailsService(oauth2DataSource);
        }

        @Override
        public void configure(ClientDetailsServiceConfigurer clients) throws Exception {

            clients.jdbc(oauth2DataSource)
                    .passwordEncoder(passwordEncoder)
                    .withClient("my-trusted-client")
                    .authorizedGrantTypes("password", "authorization_code", "refresh_token", "implicit")
                    .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
                    .scopes("read", "write", "trust")
                    .resourceIds("oauth2-resource")
                    .accessTokenValiditySeconds(60).and()
                    .withClient("my-client-with-registered-redirect")
                    .authorizedGrantTypes("authorization_code")
                    .authorities("ROLE_CLIENT")
                    .scopes("read", "trust")
                    .resourceIds("oauth2-resource")
                    .redirectUris(redirectUri).and()
                    .withClient("my-client-with-secret")
                    .authorizedGrantTypes("password", "client_credentials")
                    .authorities("ROLE_CLIENT")
                    .scopes("read")
                    .resourceIds("oautn2-resource");
            super.configure(clients);
        }

        @Override
        public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
            super.configure(security);
            security.allowFormAuthenticationForClients();
            security.passwordEncoder(passwordEncoder);
        }

        @Override
        public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
            super.configure(endpoints);
//            endpoints.
//                    authorizationCodeServices(authorizationCodeServices())
//                    .tokenStore(tokenStore())
//                    .userApprovalHandler(new TakinUserApprovalHandler())
//                    .authenticationManager(authenticationManager);
            endpoints.authorizationCodeServices(authorizationCodeServices())
                    .tokenStore(tokenStore())
                    .approvalStore(approvalStore(tokenStore()))
                    .userApprovalHandler(new TakinUserApprovalHandler())
                    .authenticationManager(authenticationManager)
                    .userDetailsService(new JdbcDaoImpl())
                    .approvalStoreDisabled();
        }
    }

}
