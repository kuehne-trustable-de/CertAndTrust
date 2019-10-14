package de.trustable.ca3s.acmeUpdater;

import static org.junit.Assert.*;

import java.io.IOException;

import org.junit.Test;

public class AcmeUpdaterTest {

	
	@Test
	public void testProcessInput() throws IOException {
		AcmeUpdater au = new AcmeUpdater();
		
		String acctStoreFilename = "AcctStore_" + System.currentTimeMillis() + ".p12";
		String domainStoreFilename = "DomainStore_" + System.currentTimeMillis() + ".p12";
		String[] args = {
				"-accountStore", acctStoreFilename,
				"-alias", "testAlias",
				"-domain", "test.trustable.de",
//				"-http01Port", "80",
				"-password", "secret99",
				"-store", domainStoreFilename,
//				"-type", "PKCS12",
				"-url", "https://acme-staging-v02.api.letsencrypt.org/directory",
				"-v"
		};
		
		int ret = au.processInput(args);
		
	}

}
