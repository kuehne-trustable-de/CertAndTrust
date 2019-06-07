package de.trustable.ca3s.acmeUpdater;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

import javax.naming.NamingException;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.KeyPairUtils;

import de.trustable.ca3s.acmeClientImpl.AcmeClient;
import de.trustable.ca3s.acmeClientImpl.CSRParameter;
import de.trustable.ca3s.acmeClientImpl.KeyCertBundle;


/**
 * Hello world!
 *
 */
public class AcmeUpdater 
{

	String keystoreFileName = "C:\\DB2\\NODE0000\\ssl_server\\mydbserver.kdb";
//	String keystoreFileName = "C:\\DB2\\NODE0000\\ssl_server\\acmeTestStore.kdb";
	String keystorePassword = "S3cr3t!99";
	char[] keystorePasswordChars;
	String keystoreType = "PKCS12";

	String keyAlias = "db2Server";
//	String keyAlias = "genericServer";
	String acmeDirUrl = "http://localhost:23880/acme/foo/directory";

	String hostname = null;

    private KeyPair accountKeyPair = KeyPairUtils.createKeyPair(2048);

	public static void main( String[] args ) throws Exception
	{
		System.out.println( "AcmeUpdater" );
		AcmeUpdater au = new AcmeUpdater();
		au.processInput(args);
	}

	public AcmeUpdater() {
		Security.addProvider(new BouncyCastleProvider());
	}
	
	
	
	public int processInput( String[] args ) throws IOException
	{
		
		keystorePasswordChars = keystorePassword.toCharArray();
		
		if( hostname == null) {
			try {
				hostname = InetAddress.getLocalHost().getHostName();
			} catch (UnknownHostException e) {
				LOG.error("retrieving host name failed with exception", e);
				return 1;
			}
		}

		File keystoreFile = new File(keystoreFileName);

		boolean bWrite = false;
		try {

			KeyStore keyStore = KeyStore.getInstance(keystoreType, BouncyCastleProvider.PROVIDER_NAME );
			keyStore.load(null, keystorePasswordChars);

			if(keystoreFile.exists()) {
				if(!keystoreFile.canRead()) {
					LOG.error("No read access for keystore '"+keystoreFile.getAbsolutePath()+"', exiting." );
					return 1;
				}
				if(!keystoreFile.canWrite()) {
					LOG.error("No write access for keystore '"+keystoreFile.getAbsolutePath()+"', exiting." );
					return 1;
				}
				try( FileInputStream storeStream = new FileInputStream(keystoreFile)){
					try {
//						keyStore = KeyStore.getInstance(keystoreFile, keystorePassword.toCharArray());
						keyStore.load(storeStream, keystorePasswordChars);
					} catch (GeneralSecurityException e) {
						LOG.error("keystore.load(stream, ****) failed with exception", e);
					}
				}    			

			}else {
				LOG.debug("keystore '"+keystoreFile.getAbsolutePath()+"' does not exists, creating ..." );
				bWrite = true;
			}

			for( Enumeration<String> enAlias = keyStore.aliases(); enAlias.hasMoreElements(); ) {
				String alias = enAlias.nextElement();
				LOG.debug("Initial key store contains alias " + alias + ": isKey " + keyStore.isKeyEntry(alias)
				+ ", isCert " + keyStore.isCertificateEntry(alias)
				+ ", Cert " + ((X509Certificate)(keyStore.getCertificate(alias))).getSubjectDN().getName());

			}

			bWrite |= updateKeyAndCertificate(keyStore, keyAlias);
			
			if(bWrite) {
				try( FileOutputStream storeStream = new FileOutputStream(keystoreFile)){
					LOG.debug("writing updated keystore file '"+keystoreFile.getAbsolutePath()+"' ..." );
					keyStore.store(storeStream, keystorePasswordChars);
				}
			}
		} catch (GeneralSecurityException | AcmeException | NamingException e) {
			LOG.error("Failed with exception", e);
			return 1;
		}

		return 0;
	}

	private boolean updateKeyAndCertificate(KeyStore keyStore, String alias) throws AcmeException, IOException, KeyStoreException, NamingException {

		if( keyStore.containsAlias(alias)) {
			LOG.debug("updating existing entry '"+alias+"' ..." );
		}else {
			LOG.debug("alias '"+alias+"' not found in keystore" );
			return false;
		}
		
		if( !keyStore.isKeyEntry(alias)) {
			LOG.debug("alias '"+alias+"' does not identify a key entry!" );
			return false;
		}
		
		CSRParameter csrParam = new CSRParameter((X509Certificate)keyStore.getCertificate(alias));
		LOG.debug("alias '"+alias+"' rerenewed with params: " + csrParam );
		
		
		AcmeClient acmeClient = new AcmeClient();
		KeyCertBundle kbr = acmeClient.getKeyCertBundle(alias, csrParam, accountKeyPair, acmeDirUrl);

		for( X509Certificate cert: kbr.getCertificateChain()) {
			
			String certAlias = keyStore.getCertificateAlias(cert);

			if( certAlias == null ) {
				LOG.debug("new certificate in the returned chain" );
			}else {
				LOG.debug("chain certificate present with alias '"+certAlias+"' " );
			}

		}
		
//		keyStore.setCertificateEntry("intermediate", kbr.getCertificateChain()[kbr.getCertificateChain().length -2]);
		
		keyStore.setCertificateEntry("ROOT", kbr.getCertificateChain()[kbr.getCertificateChain().length -1]);
		LOG.debug("alias for ROOT: " + keyStore.getCertificateAlias(kbr.getCertificateChain()[kbr.getCertificateChain().length -1]));
		
	    KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(keystorePasswordChars);
	    PrivateKeyEntry pkEntry = new PrivateKeyEntry((PrivateKey) kbr.getKey(), kbr.getCertificateChain());
	    keyStore.setEntry(alias, pkEntry, protParam);
	    
//		keyStore.setKeyEntry(alias, kbr.getKey(), keystorePassword.toCharArray(), kbr.getCertificateChain());

		
		return true;
	}
	
	
}
