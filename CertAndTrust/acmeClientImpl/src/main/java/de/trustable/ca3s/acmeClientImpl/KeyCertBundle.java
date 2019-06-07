package de.trustable.ca3s.acmeClientImpl;

import java.security.Key;
import java.security.cert.X509Certificate;
import java.util.Date;

public class KeyCertBundle {

	String alias;
	
	X509Certificate[] certificateChain;

	X509Certificate certificate;

	Key key;
	
	Date creationDate;
	
	
	public KeyCertBundle( final String alias, final X509Certificate[] certificateChain, final X509Certificate certificate, final Key key) {
		this.alias = alias;
		this.certificateChain = certificateChain.clone(); 
		this.certificate = certificate;
		this.key = key;
		this.creationDate = new Date();
	}

	/**
	 * @return the alias
	 */
	public String getAlias() {
		return alias;
	}

	/**
	 * @return the certificateChain
	 */
	public X509Certificate[] getCertificateChain() {
		return certificateChain.clone();
	}

	/**
	 * @return the certificate
	 */
	public X509Certificate getCertificate() {
		return certificate;
	}

	/**
	 * @return the key
	 */
	public Key getKey() {
		return key;
	}

	/**
	 * @return the creationDate
	 */
	public Date getCreationDate() {
		return creationDate;
	}
	
	
}
