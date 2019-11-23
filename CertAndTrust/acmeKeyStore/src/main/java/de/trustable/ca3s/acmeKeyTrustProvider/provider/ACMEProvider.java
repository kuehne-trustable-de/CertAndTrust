package de.trustable.ca3s.acmeKeyTrustProvider.provider;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ACMEProvider extends Provider {

	public static final String SERVICE_NAME_ACME = "ACME";
	private static final String STORE_TYPE_KEYSTORE = "Keystore";

	/**
	 * 
	 */
	private static final long serialVersionUID = -2476288508778039686L;

    private static final Logger LOG = LoggerFactory.getLogger(ACMEProvider.class);

	public ACMEProvider() {
		super("ACMEProvider", 1.0, "Certificate provider based on ACME");
		
		super.put("Keystore.ACME", AcmeKeyStoreImpl.class.getName());
		super.put("Keystore.ACME storetype", "ACME");

//		putService( new ProviderService(this, STORE_TYPE_KEYSTORE, SERVICE_NAME_ACME, AcmeKeyStoreImpl.class.getName()));
		
		LOG.debug("registered AcmeKeyStoreImpl in ACMEProvider");
		
		for( String prop: super.stringPropertyNames()){
			LOG.debug("provider attribute {} : '{}'", prop, this.getProperty(prop));
		}

	}

	private static final class ProviderService extends Provider.Service{
		ProviderService( Provider p, String type, String algo, String cn){
			super(p, type, algo, cn, null, null); 
		}
		
		@Override
		public Object newInstance(Object ctrParamObj) throws NoSuchAlgorithmException{
			
			String type = getType();
			String algo = getAlgorithm();
			
			try {
				if( STORE_TYPE_KEYSTORE.equalsIgnoreCase(type)) {
					if( SERVICE_NAME_ACME.equalsIgnoreCase(algo)) {
						return new AcmeKeyStoreImpl();
					}
				}
			}catch(Exception ex ) {
				throw new NoSuchAlgorithmException("Error constructing " + type + " for " + algo + "using ACMEProvider ");
			}
			throw new NoSuchAlgorithmException("No impl for " + type + " / " + algo );
		}
	}
}
