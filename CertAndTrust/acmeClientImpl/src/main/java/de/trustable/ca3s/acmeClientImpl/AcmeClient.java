package de.trustable.ca3s.acmeClientImpl;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.security.KeyPair;
import java.time.Duration;
import java.time.Instant;

import org.shredzone.acme4j.Account;
import org.shredzone.acme4j.AccountBuilder;
import org.shredzone.acme4j.Authorization;
import org.shredzone.acme4j.Metadata;
import org.shredzone.acme4j.Order;
import org.shredzone.acme4j.Session;
import org.shredzone.acme4j.Status;
import org.shredzone.acme4j.challenge.Http01Challenge;
import org.shredzone.acme4j.exception.AcmeException;
import org.shredzone.acme4j.util.CSRBuilder;
import org.shredzone.acme4j.util.KeyPairUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.takes.Take;
import org.takes.facets.fork.FkRegex;
import org.takes.facets.fork.TkFork;
import org.takes.http.Exit;
import org.takes.http.FtBasic;


/**
 * AcmeClient, handling the call to the server and the HTTP auth callbacks
 *
 */
public class AcmeClient 
{
	
    private static final Logger LOG = LoggerFactory.getLogger(AcmeClient.class);
    
	public KeyCertBundle getKeyCertBundle(String alias, final CSRParameter csrParameter, KeyPair accountKeyPair ) throws AcmeException, IOException {

		
		String dirUrl = alias;
		if( alias.contains("@")) {
			String[] parts = alias.split("@");
			if( parts.length != 2) {
				LOG.warn("Expecting zero or one ampersand in the alias separating ACME server URL from account id: acctId@http://acme.server.org/directory");
			}
			dirUrl = parts[1];
		}
		return getKeyCertBundle(alias, csrParameter, accountKeyPair, dirUrl );
	}
	
	public KeyCertBundle getKeyCertBundle(final String alias, final CSRParameter csrParameter, KeyPair accountKeyPair, String dirUrl ) throws AcmeException, IOException {
		
		LOG.debug("connecting to " + dirUrl );
		Session session = new Session(dirUrl);
		Metadata meta = session.getMetadata();
		
		URI tos = meta.getTermsOfService();
		URL website = meta.getWebsite();
		LOG.debug("TermsOfService {}, website {}", tos, website);
		
		
		AccountBuilder accBuilder = new AccountBuilder().useKeyPair(accountKeyPair);
		if( tos != null) {
			accBuilder.agreeToTermsOfService();
		}
		
		Account account = accBuilder.create(session);
		
		Order order = account.newOrder()
		        .domains(csrParameter.getDomains())
//		        .identifier(Identifier.ip(InetAddress.getByName("192.168.56.10")))
		        .notAfter(Instant.now().plus(Duration.ofDays(20L)))
		        .create();
		
		
		for (Authorization auth : order.getAuthorizations()) {
			processAuth(auth);
		}
		
		KeyPair domainKeyPair = KeyPairUtils.createKeyPair(2048);

		CSRBuilder csrb = new CSRBuilder();
		
		csrb.addDomains(csrParameter.getDomains());
		csrb.addIPs(csrParameter.getIps());
		if( csrParameter.getCountry() != null) {
			csrb.setCountry(csrParameter.getCountry());
		}
		if( csrParameter.getLocality() != null) {
			csrb.setLocality(csrParameter.getLocality());
		}
		if( csrParameter.getOrganization() != null) {
			csrb.setOrganization(csrParameter.getOrganization());
		}
		if( csrParameter.getOrganizationUnit() != null) {
			csrb.setOrganizationalUnit(csrParameter.getOrganizationUnit());
		}
		if( csrParameter.getState() != null) {
			csrb.setState(csrParameter.getState());
		}		
		
		csrb.sign(domainKeyPair);
		byte[] csr = csrb.getEncoded();
		
		order.execute(csr);
		org.shredzone.acme4j.Certificate acmeCert = order.getCertificate();
		if( acmeCert == null) {
			throw new AcmeException("Failed to retrive certificate for order");
		}
		
		java.security.cert.X509Certificate x509Cert = acmeCert.getCertificate();
		LOG.debug("certificate retrieved from ACME server {}", x509Cert.getSubjectDN().getName());
		
		java.security.cert.X509Certificate[] chain = acmeCert.getCertificateChain().toArray(new java.security.cert.X509Certificate[0]);
		int i = 0;
		for( java.security.cert.X509Certificate cert: chain) {
			LOG.debug("certificate at chain[{}] {}", i++, cert.getSubjectDN().getName());
		}
		
		return new KeyCertBundle( alias, chain, x509Cert, domainKeyPair.getPrivate());
	}

	
	private void processAuth(final Authorization auth) throws AcmeException {

	    Http01Challenge challenge = auth.findChallenge(Http01Challenge.TYPE);

	    final String fileNameRegEx = "/\\.well-known/acme-challenge/" + challenge.getToken();
	    String fileContent   = challenge.getAuthorization();

		LOG.debug("Handling authorization for {}", fileNameRegEx);

	    try {
			Take tk = new TkFork(new FkRegex(fileNameRegEx, fileContent));
			final FtBasic webBasic = new FtBasic(tk, 8800);
			
			final Exit exitOnValid = new Exit() {
				@Override
				public boolean ready() {
					return (auth.getStatus() == Status.VALID);
				}};
	
			new Thread(new Runnable() {
			     @Override
			     public void run() {
					try{
						webBasic.start(exitOnValid);
						LOG.debug("ACME callback webserver finished for {}", fileNameRegEx);
					}catch( IOException ioe) {
						LOG.warn("exception occur running webserver in extra thread", ioe);
					}
			     }
			}).start();
			
			
			LOG.debug("started ACME callback webserver for {}", fileNameRegEx);
			
		    challenge.trigger();
	
		    while (auth.getStatus() != Status.VALID) {
		    	
				LOG.debug("Authorization not yet valid for {}", fileNameRegEx);
		        Thread.sleep(500L);
		        auth.update();
		    }

			LOG.debug("Authorization solved for {}", fileNameRegEx);

	    }catch( IOException | InterruptedException ex) {
	    	throw new AcmeException("problem processing challange", ex);
	    }
	    
	}



}
