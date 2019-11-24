package de.trustable.ca3s.acmeKeyTrustProvider.provider;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Date;
import java.util.Enumeration;
import java.util.Properties;
import java.util.Set;
import java.util.Vector;
import java.util.function.Consumer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import de.trustable.ca3s.acmeClientImpl.KeyCertBundle;

public class AcmeKeyStoreImpl extends KeyStoreSpi{

    private static final Logger LOG = LoggerFactory.getLogger(AcmeKeyStoreImpl.class);

    
     public AcmeKeyStoreImpl() {
		LOG.debug("cTor AcmeKeyStoreImpl() called");
    }
    
    

	@Override
	public Key engineGetKey(String alias, char[] password) throws NoSuchAlgorithmException, UnrecoverableKeyException {
		
		LOG.debug("engineGetKey({}, ***** )", alias);
		
		KeyCertBundle kcb = TimedRenewalCertMap.getInstance().findBundleForAlias(alias);
		if( kcb == null ) {
			LOG.debug("engineGetKey({}, ***** ) throws UnrecoverableKeyException ", alias);
			throw new UnrecoverableKeyException("alias '" + alias + "' unknown");
		}

		return kcb.getKey();
	}

	@Override
	public Certificate[] engineGetCertificateChain(String alias) {
		
		LOG.debug("engineGetCertificateChain({})", alias);

		KeyCertBundle kcb = TimedRenewalCertMap.getInstance().findBundleForAlias(alias);
		if( kcb == null ) {
			LOG.info("alias '" + alias + "' unknown");
			return null;
		}
		LOG.debug("engineGetCertificateChain({} ) return chain with {} elements", alias, kcb.getCertificateChain().length);
		return kcb.getCertificateChain();
	}

	@Override
	public Certificate engineGetCertificate(String alias) {
		
		LOG.debug("engineGetCertificate({})", alias);

		KeyCertBundle kcb = TimedRenewalCertMap.getInstance().findBundleForAlias(alias);
		if( kcb == null ) {
			LOG.info("alias '" + alias + "' unknown");
			return null;
		}
		return kcb.getCertificate();
	}

	@Override
	public Date engineGetCreationDate(String alias) {
		LOG.debug("engineGetCreationDate({})", alias);

		KeyCertBundle kcb = TimedRenewalCertMap.getInstance().findBundleForAlias(alias);
		if( kcb == null ) {
			LOG.info("alias '" + alias + "' unknown");
			return null;
		}
		return kcb.getCreationDate();
	}

	@Override
	public void engineSetKeyEntry(String alias, Key key, char[] password, Certificate[] chain)
			throws KeyStoreException {
		LOG.debug("engineSetKeyEntry({}, chain)", alias, chain.length);
		
		TimedRenewalCertMap.getInstance().put( alias, chain, chain[0], key);

//		throw new RuntimeException("engineSetKeyEntry not supported");
	}

	@Override
	public void engineSetKeyEntry(String alias, byte[] key, Certificate[] chain) throws KeyStoreException {
		throw new RuntimeException("engineSetKeyEntry not supported");
		
	}

	@Override
	public void engineSetCertificateEntry(String alias, Certificate cert) throws KeyStoreException {
		throw new RuntimeException("engineSetCertificateEntry not supported");
	}

	@Override
	public void engineDeleteEntry(String alias) throws KeyStoreException {
		throw new RuntimeException("engineDeleteEntry not supported");
		
	}

	@Override
	public Enumeration<String> engineAliases() {
		LOG.debug("engineAliases()");
		
		Set<String> aliasSet = TimedRenewalCertMap.getInstance().aliases();
		for( String alias: aliasSet) {
			LOG.debug("returning alias {}", alias);
		}
		Vector<String> v = new Vector<String>(aliasSet);
/*		
		if( v.isEmpty()) {
			Properties props = System.getProperties();
			Set keys = props.keySet();
			Consumer action = new Consumer() {

				@Override
				public void accept(Object t) {
					LOG.debug("Prop key {} has value {}",t,  props.getProperty((String) t));
					
				}};
			keys.forEach(action);
			
			v.add("http://localhost:8081/acme/foo/directory");
			LOG.debug("returning alias http://localhost:8081/acme/foo/directory");
		}
*/
		
		return v.elements();
	}

	@Override
	public boolean engineContainsAlias(String alias) {
		LOG.debug("engineContainsAlias({})", alias);

		return TimedRenewalCertMap.getInstance().containsAlias(alias);
	}

	@Override
	public int engineSize() {
		LOG.debug("engineSize()");
		return TimedRenewalCertMap.getInstance().size();
	}

	@Override
	public boolean engineIsKeyEntry(String alias) {
		LOG.debug("engineIsKeyEntry({})", alias);
		KeyCertBundle kcb = TimedRenewalCertMap.getInstance().findBundleForAlias(alias);
		if( kcb != null ) {
			LOG.info("alias '" + alias + "' found");
			return true;
		}
		return false;
	}

	@Override
	public boolean engineIsCertificateEntry(String alias) {
		LOG.debug("engineIsCertificateEntry({})", alias);
		
		// private key entries only
		return false;
		
	}

	@Override
	public String engineGetCertificateAlias(Certificate cert) {
		LOG.debug("engineIsCertificateEntry({})", cert.toString());

		return TimedRenewalCertMap.getInstance().getAliasForCertificate(cert);
	}

	@Override
	public void engineStore(OutputStream stream, char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		LOG.debug("engineStore(stream, ****) : nothing to do");
	}

	@Override
	public void engineLoad(InputStream stream, char[] password)
			throws IOException, NoSuchAlgorithmException, CertificateException {
		
		LOG.info("engineLoad(stream, ****) : retrieving certificate (if neccessary)");
		
	}

	
}
