package de.trustable.ca3s.acmeKeyTrustStore.provider;

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
	
    
    public static TimedRenewalCertMap getInstance() {
    	return instance;
    }

    
    static TimedRenewalCertMap instance = new TimedRenewalCertMap();
    
    private TimedRenewalCertMap() {
		LOG.debug("cTor TimedRenewalCertMap()");
		
		TimerTask repeatedTask = new TimerTask() {
	        public void run() {
	            LOG.info("Task 'renewal' started on " + new Date());
	            
	    		for( KeyCertBundle kcb: bundleSet.values()) {
		            LOG.info("chcking renewal for alias '{}', expiring on {} ", kcb.getAlias(), kcb.getCertificate().getNotAfter() );
	    		}

	        }
	    };
	    Timer timer = new Timer("Timer");
	     
	    long delay  = 30L * 60L * 1000L;
	    long period = 30L * 60L * 1000L;
	    timer.scheduleAtFixedRate(repeatedTask, delay, period);
	    
    }
    
    
	public KeyCertBundle findBundleForAlias(String alias) {
		
//		LOG.info("findBundleForAlias('{}') called", alias);
		
//		String bundleName = alias.toUpperCase();
		String bundleName = alias;
		int callbackPort = 5544;
		
		if( !bundleSet.containsKey(bundleName) ) {
			LOG.warn("findBundleForAlias('{}') failed to find KeyCertBundle", bundleName);
			try {
				InetAddress ip = InetAddress.getLocalHost();
				CSRParameter csrParam = new CSRParameter(ip.getHostName());
				LOG.debug("requesting certificate : " + csrParam );
				AcmeClient acmeClient = new AcmeClient();
				KeyCertBundle kbr = acmeClient.getKeyCertBundle(alias, csrParam, accountKeyPair, callbackPort);
				bundleSet.put(bundleName, kbr);
				LOG.debug("succeeded to retrieve certificate from ACME-Server");
			} catch(AcmeException | IOException ex) {
				LOG.warn("failed to retrieve certificate from ACME-Server", ex);
			}
		}
		
		KeyCertBundle kcb = bundleSet.get(bundleName);
		if( kcb != null) {
			X509Certificate x509Cert = (X509Certificate) kcb.getCertificate();
			LOG.info("findBundleForAlias('{}') returns {}", alias, x509Cert.getSubjectX500Principal().getName());
		}
		
		return kcb;
		
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
