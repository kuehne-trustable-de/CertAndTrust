package de.trustable.ca3s.acmeClientImpl;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.ByteArrayInputStream;
import java.security.GeneralSecurityException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;

import javax.naming.NamingException;

import org.junit.Test;

public class CSRParameterTest {

	static final String TEST_CERT = 
			"-----BEGIN CERTIFICATE-----\r\n" + 
			"MIIEDzCCAvegAwIBAgITFQAAAFTJPRyDtFI2wgAAAAAAVDANBgkqhkiG9w0BAQsF\r\n" + 
			"ADAcMRowGAYDVQQDExFXUy0yMDE5LUlzc3VpbmdDQTAeFw0xOTA2MDcwOTE0MDla\r\n" + 
			"Fw0yMDA0MTgxMjA4NDJaMF8xCzAJBgNVBAYTAkRFMREwDwYDVQQHEwhIYW5ub3Zl\r\n" + 
			"cjESMBAGA1UEChMJdHJ1c3RhYmxlMQ8wDQYDVQQLEwZkZXZEYjIxGDAWBgNVBAMT\r\n" + 
			"D0RFU0tUT1AtSjJDRjc0VjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\r\n" + 
			"AK6zG3aJEb8kabWRjIuoMYm68S3eRMrJEcuP2bBcubatoUcp0OYs3Mq/v77hOImA\r\n" + 
			"AuNaVZwyPGk5pspvDp9cQknRoPL/r3pVDbgzohMV4TfT3nHacoquyaIfN8dYJOl5\r\n" + 
			"toOy6V6JVJZCvbscwPmHK6N5mnHLFXm90zXoFekp638Z7wuYzOSAbd6tTP7BOubY\r\n" + 
			"Ak8sMdVujxdhZioR4xWkVCpFBruow3CCnycPG+f4NMF4/lxSiWSBeIStWeQKBMGe\r\n" + 
			"4tW8v6CejirnNpDUdec3kGfrXSRbw+SS7r5fJ6O7YbkG32YMdJzjQGB0bqW+aDaM\r\n" + 
			"43PzdhrsSd07Pb3Gqj0mMpMCAwEAAaOCAQUwggEBMB0GA1UdDgQWBBTAhRpDnzcY\r\n" + 
			"6y6r5cF1VpUMGhmsIDAfBgNVHSMEGDAWgBT2QYp0sXsOUOjJRxtzM9KE/rB7GDBK\r\n" + 
			"BgNVHR8EQzBBMD+gPaA7hjlmaWxlOi8vLy9XSU4tSjRFRkNTQVJFTjkvQ2VydEVu\r\n" + 
			"cm9sbC9XUy0yMDE5LUlzc3VpbmdDQS5jcmwwZQYIKwYBBQUHAQEEWTBXMFUGCCsG\r\n" + 
			"AQUFBzAChklmaWxlOi8vLy9XSU4tSjRFRkNTQVJFTjkvQ2VydEVucm9sbC9XSU4t\r\n" + 
			"SjRFRkNTQVJFTjlfV1MtMjAxOS1Jc3N1aW5nQ0EuY3J0MAwGA1UdEwEB/wQCMAAw\r\n" + 
			"DQYJKoZIhvcNAQELBQADggEBAF27NpIdyB0EvrfP5PF0tHzuLhptSBETwm6412Nr\r\n" + 
			"9MP/VWjVhFxBNPzP95LTuvm2WIwaUwT/QtZG/rDBZZI9QZNhAXD4sS/LYQUX0jBN\r\n" + 
			"bytvcAScefqtmm1p/IissuSmCIi2KOAVHYclci7EXoQtNKwHEMFB3L8KcUbCnq94\r\n" + 
			"/1/OMKP9/+/Gn+jZN5odS+BTAYD04/XpIM4IQ/b9nj9/y81bUbzlb4oRxPX7afYh\r\n" + 
			"9MprUNufkPW7WjHSr77gpujtO5MsxzNbjORLzFzQit7a75EKlIW+Ruzi0tWp7+gM\r\n" + 
			"5Hqo++xiGTKnzREGjsyZZnLVcQvBjtssvxeKEFHIC1mdXfI=\r\n" + 
			"-----END CERTIFICATE-----";
	
	@Test
	public void test() throws GeneralSecurityException, NamingException {
		
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
	    Collection c = cf.generateCertificates(new ByteArrayInputStream( TEST_CERT.getBytes()));
	    
	    CSRParameter csrParam = new CSRParameter((X509Certificate)c.iterator().next());
	    
	    assertNotNull(csrParam.getDomains());
	    assertEquals(1, csrParam.getDomains().size());
	    assertEquals("desktop-j2cf74v".toUpperCase(), csrParam.getDomains().iterator().next().toUpperCase());

	    assertNotNull(csrParam.getIps());
	    assertEquals(0, csrParam.getIps().size());
	    
	    assertNotNull(csrParam.getOrganization());
	    assertEquals("trustable", csrParam.getOrganization());
	    
	    assertNotNull(csrParam.getOrganizationUnit());
	    assertEquals("devDb2", csrParam.getOrganizationUnit());
	    
	    assertNotNull(csrParam.getLocality() );
	    assertEquals("Hannover", csrParam.getLocality());
	    
	    assertNull(csrParam.getState());
	    
	    assertNotNull(csrParam.getCountry() );
	    assertEquals("DE", csrParam.getCountry());
	    
	    

	}

}
