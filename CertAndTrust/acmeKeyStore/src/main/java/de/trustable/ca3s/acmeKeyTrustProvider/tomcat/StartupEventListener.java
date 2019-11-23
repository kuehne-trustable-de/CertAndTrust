package de.trustable.ca3s.acmeKeyTrustProvider.tomcat;

import java.security.Security;

import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleEvent;
import org.apache.catalina.LifecycleListener;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.trustable.ca3s.acmeKeyTrustProvider.provider.ACMEProvider;
import de.trustable.ca3s.acmeKeyTrustProvider.provider.TSLProvider;


/**
 * 
 * Initialize the JCA stuff and make the LocalADCSProvider available 
 * 
 * @author kuehn
 *
 */
public class StartupEventListener implements LifecycleListener {
	
    private static final Logger LOG = LoggerFactory.getLogger(StartupEventListener.class);

    static ACMEProvider acmeProvider = new ACMEProvider();
    
	@Override
	public void lifecycleEvent(LifecycleEvent arg0) {

		if( Security.getProvider(acmeProvider.getName()) == null ) {
			System.out.println("lifecycleEvent, registering provider " + acmeProvider.getName() + ", info : " + acmeProvider.getInfo());
			Security.addProvider(acmeProvider);
		}
		
/*		
//		LOG.info("lifecycleEvent {}", arg0.toString());
		System.out.println("lifecycleEvent " + arg0.toString());

		Lifecycle lifecycle = arg0.getLifecycle();
		if (lifecycle == null) {
			return;
		}
		String type = arg0.getType();
		if (type == null) {
			return;
		}
		String stateName = lifecycle.getStateName();
		if (stateName == null) {
			return;
		}
		
		LOG.info("type {}, state {}", type, stateName);
		if ( Lifecycle.BEFORE_START_EVENT.equals(type) ) {
			
			LOG.info("type {}, state {}", type, stateName);
			
			Security.addProvider(new ACMEProvider());
//			Security.addProvider(new TSLProvider());
			
		}
*/
		
	}

}
