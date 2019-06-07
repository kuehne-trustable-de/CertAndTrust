package de.trustable.ca3s.acmeKeyTrustStore.provider;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ACMEProvider extends Provider {

	/**
	 * 
	 */
	private static final long serialVersionUID = -2476288508778039686L;

    private static final Logger LOG = LoggerFactory.getLogger(ACMEProvider.class);

	public ACMEProvider() {
		super("ACMEProvider", 1.0, "Certificate provider based on ACME");
		
		super.put("Keystore.ACME", AcmeKeyStoreImpl.class.getName());
		super.put("Keystore.ACME storetype", "ACME");

//		putService( new ProviderService(this, "Keystore", "ACME", AcmeKeyStoreImpl.class.getName()));
		
		LOG.debug("registered AcmeKeyStoreImpl in ACMEProvider");
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
				if( "Storetype".equalsIgnoreCase(type)) {
					if( "ACME".equalsIgnoreCase(algo)) {
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
