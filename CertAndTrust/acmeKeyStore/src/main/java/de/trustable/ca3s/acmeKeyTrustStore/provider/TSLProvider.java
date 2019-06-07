package de.trustable.ca3s.acmeKeyTrustStore.provider;

import java.security.NoSuchAlgorithmException;
import java.security.Provider;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class TSLProvider extends Provider {

	/**
	 * 
	 */
	private static final long serialVersionUID = -2476288508778039686L;

    private static final Logger LOG = LoggerFactory.getLogger(TSLProvider.class);

	public TSLProvider() {
		super("TSLProvider", 1.0, "Truststore provider based on TSL");
		
		super.put("Keystore.TSL", TSLTrustStoreImpl.class.getName());
		super.put("Keystore.TSL storetype", "TSL");

//		putService( new ProviderService(this, "Keystore", "ACME", AcmeKeyStoreImpl.class.getName()));
		
		LOG.debug("registered TSLTrustStoreImpl in TSLProvider");
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
					if( "TSL".equalsIgnoreCase(algo)) {
						return new TSLTrustStoreImpl();
					}
				}
			}catch(Exception ex ) {
				throw new NoSuchAlgorithmException("Error constructing " + type + " for " + algo + "using TSLProvider ");
			}
			throw new NoSuchAlgorithmException("No impl for " + type + " / " + algo );
		}
	}
}
