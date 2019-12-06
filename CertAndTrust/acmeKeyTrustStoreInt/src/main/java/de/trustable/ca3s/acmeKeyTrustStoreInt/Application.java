package de.trustable.ca3s.acmeKeyTrustStoreInt;

import java.security.Provider;
import java.security.Security;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import de.trustable.ca3s.storeTester.provider.ACMEProvider;
import de.trustable.ca3s.storeTester.provider.TSLProvider;

@SpringBootApplication
@Configuration
@ComponentScan(basePackages= {"de.trustable.ca3s" })
@EnableWebMvc
public class Application {

    public static void main(String[] args) {
    	
    	
 //   	Security.addProvider( new TSLProvider());
    	Security.addProvider( new ACMEProvider());
    	
    	for( Provider prov: Security.getProviders()) {
            System.out.println("Provider found: " +  prov.toString());
    	}

/*    	
    	for( Provider.Service service : Security.getProvider("TSLProvider").getServices()) {
            System.out.println("Service found: " +  service.toString());
    	}
*/    	
    	for( Provider.Service service : Security.getProvider("ACMEProvider").getServices()) {
            System.out.println("Service found: " +  service.toString());
    	}
        SpringApplication.run(Application.class, args);
        
    }

    @Bean
    public CommandLineRunner commandLineRunner(ApplicationContext ctx) {
        return args -> {

            System.out.println("SimpleStoreTester started");
/*            
            for (String beanName : ctx.getBeanDefinitionNames()) {
                System.out.println(beanName);
            }
*/
        };
    }

}