package de.trustable.ca3s.acmeClientImpl;

import java.net.InetAddress;
import java.security.cert.X509Certificate;
import java.util.ArrayList;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

public class CSRParameter {

	ArrayList<String> domains = new ArrayList<String>();
	ArrayList<InetAddress> ips = new ArrayList<InetAddress>();

	String organization;
	String organizationUnit;
	String locality;
	String state;
	String country;
	
	public CSRParameter(String domain) {
		domains.add(domain);
	}

	public CSRParameter(String domain, String organization, String organizationUnit,String locality, String state, String country) {
		this.domains.add(domain);
		this.organization = organization;
		this.organizationUnit =	organizationUnit;
		this.locality = locality;
		this.state = state;
		this.country = country;
	}

	public CSRParameter(X509Certificate certificate) throws InvalidNameException {
		
		
		String dn = certificate.getSubjectX500Principal().getName();
		LdapName ln = new LdapName(dn);

		for(Rdn rdn : ln.getRdns()) {
		    if(rdn.getType().equalsIgnoreCase("CN")) {
		    	this.domains.add(rdn.getValue().toString());
		    }else if(rdn.getType().equalsIgnoreCase("O")) {
		    	this.organization= rdn.getValue().toString();
		    }else if(rdn.getType().equalsIgnoreCase("OU")) {
		    	this.organizationUnit= rdn.getValue().toString();
		    }else if(rdn.getType().equalsIgnoreCase("L")) {
		    	this.locality = rdn.getValue().toString();
		    }else if(rdn.getType().equalsIgnoreCase("ST")) {
		    	this.state= rdn.getValue().toString();
		    }else if(rdn.getType().equalsIgnoreCase("C")) {
		    	this.country =rdn.getValue().toString();
		    }
		}
		
		
	}

	public String toString() {
	
		String res = "";
		if( !this.domains.isEmpty()) {
			res = "Domains: ";
			for(String domain: this.domains) {
				res += "'" + domain + "' ";
			}
			res += "\n";
		}
		
		if( !this.ips.isEmpty()) {
			res = "IPs: ";
			for(InetAddress ip: this.ips) {
				res += "'" + ip + "' ";
			}
			res += "\n";
		}
		
		if( this.organization != null) {
			res += "O:" + this.organization + "\n";
		}
		
		if( this.organizationUnit != null) {
			res += "OU:" + this.organizationUnit + "\n";
		}
		
		if( this.locality != null) {
			res += "L:" + this.locality  + "\n";
		}
		
		if( this.state != null) {
			res += "ST:" + this.state + "\n";
		}
		
		if( this.country != null) {
			res += "C:" + this.country + "\n";
		}
		
		return res;
	}
	
	/**
	 * @return the domains
	 */
	public ArrayList<String> getDomains() {
		return domains;
	}

	/**
	 * @param domains the domains to set
	 */
	public void setDomains(ArrayList<String> domains) {
		this.domains = domains;
	}

	/**
	 * @param domains the domains to set
	 */
	public void addDomain(String domain) {
		this.domains.add(domain);
	}

	/**
	 * @return the ips
	 */
	public ArrayList<InetAddress> getIps() {
		return ips;
	}

	/**
	 * @param ips the ips to set
	 */
	public void setIps(ArrayList<InetAddress> ips) {
		this.ips = ips;
	}

	/**
	 * @param ips the ips to set
	 */
	public void addIp(InetAddress ip) {
		this.ips.add(ip);
	}

	/**
	 * @return the organization
	 */
	public String getOrganization() {
		return organization;
	}

	/**
	 * @param organization the organization to set
	 */
	public void setOrganization(String organization) {
		this.organization = organization;
	}

	/**
	 * @return the organizationUnit
	 */
	public String getOrganizationUnit() {
		return organizationUnit;
	}

	/**
	 * @param organizationUnit the organizationUnit to set
	 */
	public void setOrganizationUnit(String organizationUnit) {
		this.organizationUnit = organizationUnit;
	}

	/**
	 * @return the locality
	 */
	public String getLocality() {
		return locality;
	}

	/**
	 * @param locality the locality to set
	 */
	public void setLocality(String locality) {
		this.locality = locality;
	}

	/**
	 * @return the state
	 */
	public String getState() {
		return state;
	}

	/**
	 * @param state the state to set
	 */
	public void setState(String state) {
		this.state = state;
	}

	/**
	 * @return the country
	 */
	public String getCountry() {
		return country;
	}

	/**
	 * @param country the country to set
	 */
	public void setCountry(String country) {
		this.country = country;
	}

	
}
