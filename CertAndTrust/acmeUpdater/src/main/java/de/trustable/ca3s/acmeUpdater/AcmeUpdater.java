package de.trustable.ca3s.acmeUpdater;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;
import java.util.Enumeration;
import java.util.concurrent.Executor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Consumer;

import javax.naming.NamingException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.OperatorException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.kohsuke.args4j.CmdLineException;
import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.KeyPairUtils;

import de.trustable.ca3s.acmeClientImpl.AcmeClient;
import de.trustable.ca3s.acmeClientImpl.CSRParameter;
import de.trustable.ca3s.acmeClientImpl.KeyCertBundle;


/**
 * AcmeUpdater
 *
 */
public class AcmeUpdater 
{

	 @Option(name="-store", required=true, usage="name of the keystore file to process (mandatory)", metaVar="FILE")
	 String keystoreFileName = "myStore.p12";
//	 String keystoreFileName = "C:\\DB2\\NODE0000\\ssl_server\\mydbserver.kdb";
	
	 @Option(name="-password", required=false, usage="password of the keystore file (and the private key)", metaVar="STRING")
	String keystorePassword = "S3cr3t!99";
	private char[] keystorePasswordChars;
	
	 @Option(name="-type",required=false,usage="keystore type")
	StoreType keystoreType = StoreType.PKCS12;

	 @Option(name="-alias",required=false, usage="alias of the certificate to process (mandatory)", metaVar="STRING")
	String keyAlias = "db2Server";
//	String keyAlias = "genericServer";
	 
	 
	 @Option(name="-url",required=false, usage="url of the ACME server (of the directory resource)", metaVar="URL")
	String acmeDirUrl = "http://localhost:23880/acme/foo/directory";

	 @Option(name="-http01Port",required=false, usage="callback port of the ACME HTTP01 challange", metaVar="PORT")
	int callbackPort = 8800;
	 
	 @Option(name="-tosUrl",required=false, usage="url of the accepted 'terms of usage')", metaVar="URL")
	String acceptedTOSUrl = "";
	
	 @Option(name="-domain",required=false,usage="domain names to process", metaVar="DOMAIN[,DOMAIN,...]")
	String hostname = null;

	 @Option(name="-v",required=false,usage="verbose processing info")
	 boolean  bVerbose = false;
	 
	 @Option(name="-accountStore", required=false, usage="name of the keystore file holding the account credentials", metaVar="FILE")
	String accountStoreFileName = "accountStore.p12";

	@Option(name="-genpseFileName", required=false, usage="full path and file name of genpse executable", metaVar="FILE")
	String genpseExecFileName = "";

	 
    BouncyCastleProvider bcProv = new BouncyCastleProvider();
    LOG logger = new LOG();
    
	public static void main( String[] args ) throws Exception
	{
		System.out.println( "AcmeUpdater" );
		AcmeUpdater au = new AcmeUpdater();
		au.processInput(args);
	}

	public AcmeUpdater() {
		Security.addProvider(bcProv);
	}
	
	
	
	public int processInput( String[] args ) throws IOException
	{
		
	       CmdLineParser parser = new CmdLineParser(this);
	        try {
	            // parse the arguments.
	            parser.parseArgument(args);
	        } catch( CmdLineException e ) {
	            // if there's a problem in the command line,
	            // you'll get this exception. this will report
	            // an error message.
	            System.err.println(e.getMessage());
	            System.err.println("java AcmeUpdater -store keytore.p12 -alias certAlias [options...]\n");
	            // print the list of available options
	            parser.printUsage(System.err);
	            System.err.println();

	            // print option sample. This is useful some time
	            // System.err.println("  Example: java AcmeUpdater "+parser.printExample(OptionHandlerFilter.ALL));

	            return 2;
	        }

	        logger.setVerbose(bVerbose);
	        
		if( hostname == null) {
			try {
				hostname = InetAddress.getLocalHost().getCanonicalHostName();
			} catch (UnknownHostException e) {
				logger.error("retrieving host name failed with exception", e);
				return 1;
			}
		}

		File tmpP12StoreFile = null;

		File acctstoreFile = new File(accountStoreFileName);

		boolean bWrite = false;
		try {

			String accountAlias = "acct";
			char[] acctPass = "Y9frHb08izc".toCharArray();
			
			KeyStore acctStore = KeyStore.getInstance(StoreType.PKCS12.toString(), BouncyCastleProvider.PROVIDER_NAME );
			acctStore.load(null, acctPass);
			
			if(acctstoreFile.exists()) {
				if(!acctstoreFile.canRead()) {
					logger.error("No read access for account store '"+acctstoreFile.getAbsolutePath()+"', exiting." );
					return 1;
				}
				if(!acctstoreFile.canWrite()) {
					logger.error("No write access for account store '"+acctstoreFile.getAbsolutePath()+"', exiting." );
					return 1;
				}
				if( acctstoreFile.length() > 0L) {
					try( FileInputStream storeStream = new FileInputStream(acctstoreFile)){
						try {
							acctStore.load(storeStream, acctPass);
						} catch (GeneralSecurityException e) {
							logger.error("reading the account store failed with exception", e);
							return 3;
						}
					}
				}else {
					logger.error("Found empty account store '"+acctstoreFile.getAbsolutePath()+"', ignoring ..." );
				}

			}else {
				logger.debug("account store '"+acctstoreFile.getAbsolutePath()+"' does not exist." );
			}

			// handle account store content
			X509Certificate acctCert = (X509Certificate) acctStore.getCertificate(accountAlias);
			if( acctCert == null || (acctCert.getNotAfter().before(new Date()))) {
				if( acctCert == null ) {
					logger.debug("creating new account store ..." );
				}else {
					logger.debug("account certificate expired at " + acctCert.getNotAfter() + ", updating account store ..." );
				}
				
				KeyPair accountKeyPair = KeyPairUtils.createKeyPair(2048);
			    
			    X509Certificate[] acctChain = new X509Certificate[1];
			    acctCert = selfSign(accountKeyPair, "CN=AccountKeyPair");
			    acctChain[0] = acctCert;
			    
			    KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(acctPass);
			    PrivateKeyEntry pkEntry = new PrivateKeyEntry((PrivateKey) accountKeyPair.getPrivate(), acctChain);
			    acctStore.setEntry(accountAlias, pkEntry, protParam);
			    
				try( FileOutputStream storeStream = new FileOutputStream(acctstoreFile)){
					logger.debug("writing account store file '"+acctstoreFile.getAbsolutePath()+"' ..." );
					acctStore.store(storeStream, acctPass);
				}
			}

			// assume the filename is the actual store.Maybe changed to a P12-copy of the pse store 
			File keystoreFile = new File(keystoreFileName);
			String actualStoreType = keystoreType.toString();
			
			if( keystoreType == StoreType.PSE ) {
				if( genpseExecFileName.trim().length() == 0) {
					logger.error("to process pse the genpse file name MUST be given. Exiting ...");
					return 1;
				}
				
				tmpP12StoreFile = File.createTempFile("pseCopy", ".p12");
				keyAlias = "sappse";
						
				// it is expected that the target does NOT exist
				tmpP12StoreFile.delete();
				
				copyPseToP12(genpseExecFileName, keystoreFileName, keystorePassword, keyAlias, tmpP12StoreFile.getAbsolutePath());
				if( tmpP12StoreFile.exists() && tmpP12StoreFile.canRead()) {
					logger.debug("tmpP12StoreFile created '"+tmpP12StoreFile.getAbsolutePath()+ "' containing " + tmpP12StoreFile.length() + " bytes" );
					keystoreFile = tmpP12StoreFile;
					actualStoreType = StoreType.PKCS12.toString();
					
				}else {
					logger.error("Creation of P12 copy od pse failed. Exiting ...");
					return 1;
				}
				
			}
			
			
		    PrivateKey accountKey = (PrivateKey) acctStore.getKey(accountAlias, acctPass);
		    KeyPair accountKeyPair = new KeyPair(acctCert.getPublicKey(), accountKey);
			
			KeyStore keyStore = KeyStore.getInstance(actualStoreType, BouncyCastleProvider.PROVIDER_NAME );
			keystorePasswordChars = keystorePassword.toCharArray();
			keyStore.load(null, keystorePasswordChars);

			if(keystoreFile.exists()) {
				if(!keystoreFile.canRead()) {
					logger.error("No read access for keystore '"+keystoreFile.getAbsolutePath()+"', exiting." );
					return 1;
				}
				if(!keystoreFile.canWrite()) {
					logger.error("No write access for keystore '"+keystoreFile.getAbsolutePath()+"', exiting." );
					return 1;
				}
				try( FileInputStream storeStream = new FileInputStream(keystoreFile)){
					try {
						keyStore.load(storeStream, keystorePasswordChars);
					} catch (GeneralSecurityException | IOException e) {
						logger.error("reading the keystore '" + keystoreFile.getAbsolutePath()+ "' failed with exception", e);
					}
				}    			

			}else {
				logger.debug("keystore '"+keystoreFile.getAbsolutePath()+"' does not exists, creating ..." );
				bWrite = true;
			}

			for( Enumeration<String> enAlias = keyStore.aliases(); enAlias.hasMoreElements(); ) {
				String alias = enAlias.nextElement();
				logger.debug("Initial key store contains alias " + alias + ": isKey " + keyStore.isKeyEntry(alias)
				+ ", isCert " + keyStore.isCertificateEntry(alias)
				+ ", Cert " + ((X509Certificate)(keyStore.getCertificate(alias))).getSubjectDN().getName());

			}

			try {
				bWrite |= updateKeyAndCertificate(keyStore, keyAlias, accountKeyPair);
			} catch( org.shredzone.acme4j.exception.AcmeNetworkException ane) {
				logger.error("Failed to access the ACME server at '" + acmeDirUrl + "', " + ane.getMessage());
				return 1;
			}
			
			if(bWrite) {
				try( FileOutputStream storeStream = new FileOutputStream(keystoreFile)){
					logger.debug("writing updated keystore file '"+keystoreFile.getAbsolutePath()+"' ..." );
					keyStore.store(storeStream, keystorePasswordChars);
				}

				if( keystoreType == StoreType.PSE ) {
					if( tmpP12StoreFile == null) {
						logger.error("Failed to retrieve the temp. P12 Container, exiting ...");
						return 1;
					}
					if( !tmpP12StoreFile.canRead() || (tmpP12StoreFile.length() < 100) ) {
						logger.error("Temp. P12 Container ("+tmpP12StoreFile.getAbsolutePath()+") not readable / no content, exiting ...");
						return 1;
					}
					
					copyP12ToPse(genpseExecFileName, keystoreFileName, keystorePassword, keyAlias, tmpP12StoreFile.getAbsolutePath());
				}
			}
		} catch (GeneralSecurityException | AcmeException | NamingException | OperatorException e) {
			logger.error("Failed with exception", e);
			return 1;
		}

		return 0;
	}

	private void copyP12ToPse(String genpseExecFileName, String keystoreFileName, String keystorePassword, String alias, String tmpStoreFileName) {

		boolean isWindows = System.getProperty("os.name").toLowerCase().startsWith("windows");
		
		ProcessBuilder builder = new ProcessBuilder();
		if (isWindows) {
		    builder.command(genpseExecFileName, "import_p12", "-p", keystoreFileName, "-x", keystorePassword, "-z", keystorePassword, tmpStoreFileName);
		} else {
		    builder.command(genpseExecFileName, "import_p12", "-p", keystoreFileName, "-x", keystorePassword, "-z", keystorePassword, tmpStoreFileName);
		}

		executeExternalProcess(builder);
	}

	private void copyPseToP12(String genpseExecFileName, String keystoreFileName, String keystorePassword, String alias, String tmpStoreFileName) {

		boolean isWindows = System.getProperty("os.name").toLowerCase().startsWith("windows");
		
		ProcessBuilder builder = new ProcessBuilder();
		if (isWindows) {
		    builder.command(genpseExecFileName, "export_p12", "-p", keystoreFileName, "-x", keystorePassword, "-z", keystorePassword, "-F", alias,  tmpStoreFileName);
		} else {
		    builder.command(genpseExecFileName, "export_p12", "-p", keystoreFileName, "-x", keystorePassword, "-z", keystorePassword, "-F", alias,  tmpStoreFileName);
		}

		executeExternalProcess(builder);
	}

	/**
	 * @param builder
	 */
	private void executeExternalProcess(ProcessBuilder builder) {
		String cmd = "";
	    for( String s:builder.command()) {
	    	cmd += s + " ";
	    }
		logger.debug("genpse command '"+ cmd +"' " );
	    
		try {
			
			builder.directory(new File(System.getProperty("user.home")));
			builder.inheritIO();
			
			Process process = builder.start();
			StreamGobbler streamGobbler = new StreamGobbler(process.getInputStream(), System.out::println);
			ExecutorService execSrv = Executors.newSingleThreadExecutor();
			execSrv.submit(streamGobbler);
			
			int exitCode = process.waitFor();
			logger.debug("genpse exitCode '"+exitCode +"' " );
			
			execSrv.shutdownNow();
			
		}catch(InterruptedException | IOException ex) {
			logger.error("executing external process failed with exception", ex);
		}
	}

	private static class StreamGobbler implements Runnable {
	    private InputStream inputStream;
	    private Consumer<String> consumer;
	 
	    public StreamGobbler(InputStream inputStream, Consumer<String> consumer) {
	        this.inputStream = inputStream;
	        this.consumer = consumer;
	    }
	 
	    @Override
	    public void run() {
	        new BufferedReader(new InputStreamReader(inputStream)).lines()
	          .forEach(consumer);
	    }
	}
	
	/**
	 * 
	 * @param keyStore
	 * @param alias
	 * @param accountKeyPair
	 * @return
	 * @throws AcmeException
	 * @throws IOException
	 * @throws KeyStoreException
	 * @throws NamingException
	 */
	private boolean updateKeyAndCertificate(KeyStore keyStore, String alias, KeyPair accountKeyPair) throws AcmeException, IOException, KeyStoreException, NamingException {

		CSRParameter csrParam;

		if( keyStore.containsAlias(alias)) {
			logger.debug("updating existing entry '"+alias+"' ..." );
			
			if( !keyStore.isKeyEntry(alias)) {
				logger.debug("alias '"+alias+"' does not identify a key entry!" );
				return false;
			}

			csrParam = new CSRParameter((X509Certificate)keyStore.getCertificate(alias));
			logger.debug("alias '"+alias+"' rerenewed with params: " + csrParam );
			

		}else {
			logger.debug("alias '"+alias+"' not found in keystore" );
//			return false;
			
			if( hostname == null || hostname.trim().length() == 0) {
				logger.debug("entry not yet present, for creation the domain parameter is required" );
				return false;
			}
			csrParam = new CSRParameter(hostname);
			logger.debug("alias '"+alias+"' created with params: " + csrParam );
			
		}
		
		
		AcmeClient acmeClient = new AcmeClient();
		KeyCertBundle kbr = acmeClient.getKeyCertBundle(alias, csrParam, accountKeyPair, acmeDirUrl, callbackPort);

		for( X509Certificate cert: kbr.getCertificateChain()) {
			
			String certAlias = keyStore.getCertificateAlias(cert);

			if( certAlias == null ) {
				logger.debug("new certificate in the returned chain" );
			}else {
				logger.debug("chain certificate present with alias '"+certAlias+"' " );
			}

		}
		
//		keyStore.setCertificateEntry("intermediate", kbr.getCertificateChain()[kbr.getCertificateChain().length -2]);
		
//		keyStore.setCertificateEntry("ROOT", kbr.getCertificateChain()[kbr.getCertificateChain().length -1]);
//		logger.debug("alias for ROOT: " + keyStore.getCertificateAlias(kbr.getCertificateChain()[kbr.getCertificateChain().length -1]));
		
	    KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(keystorePasswordChars);
	    PrivateKeyEntry pkEntry = new PrivateKeyEntry((PrivateKey) kbr.getKey(), kbr.getCertificateChain());
	    keyStore.setEntry(alias, pkEntry, protParam);
	    
		return true;
	}
	
	/**
	 * create selfsigned certificate (for internal use only!)
	 * 
	 * @param keyPair
	 * @param subjectDN
	 * @return
	 * @throws OperatorCreationException
	 * @throws CertificateException
	 * @throws IOException
	 */
	public X509Certificate selfSign(KeyPair keyPair, String subjectDN) throws OperatorCreationException, CertificateException, IOException
	{
	    long now = System.currentTimeMillis();
	    Date startDate = new Date(now);

	    X500Name dnName = new X500Name(subjectDN);
	    BigInteger certSerialNumber = new BigInteger(Long.toString(now)); // <-- Using the current timestamp as the certificate serial number

	    Calendar calendar = Calendar.getInstance();
	    calendar.setTime(startDate);
	    calendar.add(Calendar.YEAR, 2); // <-- 2 Yr validity

	    Date endDate = calendar.getTime();

	    String signatureAlgorithm = "SHA256WithRSA"; // <-- Use appropriate signature algorithm based on your keyPair algorithm.

	    ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(keyPair.getPrivate());

	    JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(dnName, certSerialNumber, startDate, endDate, dnName, keyPair.getPublic());

	    // Extensions --------------------------

	    // Basic Constraints
	    BasicConstraints basicConstraints = new BasicConstraints(true); // <-- true for CA, false for EndEntity

	    certBuilder.addExtension(new ASN1ObjectIdentifier("2.5.29.19"), true, basicConstraints); // Basic Constraints is usually marked as critical.

	    // -------------------------------------

	    return new JcaX509CertificateConverter().setProvider(bcProv).getCertificate(certBuilder.build(contentSigner));
	}
	

	enum StoreType { PKCS12,JKS,PSE }
}


