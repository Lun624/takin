package xyz.masaimara.takin.config.data;

import com.zaxxer.hikari.HikariDataSource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.autoconfigure.jdbc.DataSourceProperties;
import org.springframework.boot.jdbc.DataSourceInitializationMode;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.context.annotation.PropertySource;

import javax.sql.DataSource;

/**
 * configuration data sources
 */

@Configuration
@PropertySource({"classpath:/datasource.properties", "classpath:/mybatis.properties"})
public class DataAccessConfiguration {
    private Logger logger = LoggerFactory.getLogger(DataAccessConfiguration.class);

    @Bean
    @Primary
    @Qualifier("takinDataSource")
    public DataSource dataSource(DataSourceProperties properties) {
        properties.setInitializationMode(DataSourceInitializationMode.NEVER);
        DataSource dataSource = properties.initializeDataSourceBuilder().type(HikariDataSource.class)
                .build();
        logger.info("data source: {}", null == dataSource);
        return dataSource;
    }

//    @Bean
//    public TransactionFactory mybatisTransactionFactory() {
//        return new JdbcTransactionFactory();
//    }

//    @Bean
//    @Qualifier("productEnvironment")
//    public Environment environment(TransactionFactory transactionFactory, @Qualifier("prototypeDataSource") DataSource dataSource) {
//        return new Environment("product", transactionFactory, dataSource);
//    }

//    @Bean
//    @Qualifier("productConfiguration")
//    public Configuration configuration(@Qualifier("productEnvironment") Environment environment) {
//        Configuration configuration = new Configuration(environment);
//        configuration.addMappers("xyz.masaimara.prototype", TestMapper.class);
//        return configuration;
//    }

//    @Bean
//    @Qualifier("productSqlSessionFactory")
//    public SqlSessionFactory sqlSessionFactory(@Qualifier("prototypeDataSource") DataSource dataSource, @Qualifier("productConfiguration") Configuration configuration) {
//        return new SqlSessionFactoryBuilder().build(configuration);
//    }
}