package de.trustable.ca3s.acmeKeyTrustProvider.provider;

import java.io.IOException;
import java.net.InetAddress;
import java.security.Key;
import java.security.KeyPair;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Set;
import java.util.Timer;
import java.util.TimerTask;

import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.exception.AcmeNetworkException;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.trustable.ca3s.acmeClientImpl.AcmeClient;
import de.trustable.ca3s.acmeClientImpl.CSRParameter;
import de.trustable.ca3s.acmeClientImpl.KeyCertBundle;

public class TimedRenewalCertMap {

    private static final Logger LOG = LoggerFactory.getLogger(TimedRenewalCertMap.class);

    private HashMap<String, KeyCertBundle> bundleSet = new HashMap<String, KeyCertBundle>();
	
    private KeyPair accountKeyPair = KeyPairUtils.createKeyPair(2048);

//	KeyPair accountKeyPair = KeyPairUtils.createECKeyPair("secp256r1");

	int callbackPort = 5544;
	
	int maxAcmeRetry = 5;

    
    public static TimedRenewalCertMap getInstance() {
    	return instance;
    }

    
    static TimedRenewalCertMap instance = new TimedRenewalCertMap();
    
    private TimedRenewalCertMap() {
		LOG.debug("cTor TimedRenewalCertMap()");
		
		TimerTask repeatedTask = new TimerTask() {
	        public void run() {
	        	
	        	Date refreshDate = new Date(System.currentTimeMillis() + (24L * 3600L * 1000L));
	            LOG.info("Task 'renewal' started on " + new Date() + ", refreshing all certificates expiring before " + refreshDate );
	            
	    		for( KeyCertBundle kcb: bundleSet.values()) {
		            LOG.debug("checking renewal for alias '{}', expiring on {} ", kcb.getAlias(), kcb.getCertificate().getNotAfter() );
		            
		            if( refreshDate.after(kcb.getCertificate().getNotAfter())) {
			            LOG.info("renewal required for alias '{}', expiring on {} ", kcb.getAlias(), kcb.getCertificate().getNotAfter() );
		    			updateKeyBundle(kcb.getAlias(), callbackPort);
		            }
	    		}

	        }
	    };
	    
	    Timer timer = new Timer("Timer");
	     
	    long delay  = 30L * 60L * 1000L;
	    long period = 30L * 60L * 1000L;
	    timer.scheduleAtFixedRate(repeatedTask, delay, period);
	    
    }
    
    
	public KeyCertBundle findBundleForAlias(final String bundleName) {
			
		if( !bundleSet.containsKey(bundleName) ) {
			LOG.warn("findBundleForAlias('{}') failed to find KeyCertBundle", bundleName);
			updateKeyBundle(bundleName, callbackPort);
		}
		
		KeyCertBundle kcb = bundleSet.get(bundleName);
		if( kcb != null) {
			X509Certificate x509Cert = (X509Certificate) kcb.getCertificate();
			LOG.info("findBundleForAlias('{}') returns {}", bundleName, x509Cert.getSubjectX500Principal().getName());
		}
		
		return kcb;
		
	}


	/**
	 * @param bundleName
	 * @param callbackPort
	 */
	private void updateKeyBundle(String bundleName, int callbackPort) {
		
		
		try {
			InetAddress ip = InetAddress.getLocalHost();
			CSRParameter csrParam = new CSRParameter(ip.getCanonicalHostName());
			LOG.debug("requesting certificate : " + csrParam );
			
			// initialize retry counter
			for( int n = 0; n < 10; n++) {
				try {
					AcmeClient acmeClient = new AcmeClient();
					KeyCertBundle kbr = acmeClient.getKeyCertBundle(bundleName, csrParam, accountKeyPair, callbackPort);
					bundleSet.put(bundleName, kbr);
					LOG.debug("succeeded to retrieve certificate from ACME-Server");
					break;
				}catch (AcmeNetworkException ane) {
					
					// connection failed, still hope for a retrial?
					if( n < maxAcmeRetry) { 
						LOG.debug("failed to connect to ACME-Server '{}', retrying ...", ane.getLocalizedMessage());
						pause(2000);
					}else {
						LOG.warn("failed to connect to ACME-Server '{}', retry count {} exceeded", ane.getLocalizedMessage(), n);
						throw ane;
					}
				}
			}
		} catch(AcmeException | IOException ex) {
			LOG.warn("failed to retrieve certificate from ACME-Server", ex);
		}
	}

	public static void pause(int ms) {
	    try {
	        Thread.sleep(ms);
	    } catch (InterruptedException e) {
	        System.err.format("IOException: %s%n", e);
	    }
	}
	
	public Set<String> aliases() {
		return bundleSet.keySet();
	}


	public boolean containsAlias(String alias) {
		return bundleSet.containsKey(alias);
	}

	public int size() {
		return bundleSet.size();
	}

	public String getAliasForCertificate(final Certificate cert) {
		
		for( KeyCertBundle kcb: bundleSet.values()) {
			if( kcb.getCertificate().equals(cert)) {
				return kcb.getAlias();
			}
		}
		return null;
	}

	public void put(String alias, Certificate[] chain, Certificate certificate, Key key) {
		
		KeyCertBundle kbr = new KeyCertBundle( alias, (X509Certificate[])chain, (X509Certificate)chain[0], key);
		bundleSet.put(alias, kbr);	
	}

}
