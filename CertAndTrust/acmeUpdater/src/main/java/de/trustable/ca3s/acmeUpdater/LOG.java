package de.trustable.ca3s.acmeUpdater;

public class LOG {

	boolean bVerbose = false;

	public void error(final String msg) {
		System.err.println(msg);
	}
	public void error(final String msg, final Throwable th) {
		System.err.println(msg);
		th.printStackTrace();
	}
	public void debug(final String msg) {
		if( bVerbose) {
			System.out.println(msg);
		}
	}
	public void setVerbose(boolean bVerbose) {
		this.bVerbose = bVerbose;
	}
}
