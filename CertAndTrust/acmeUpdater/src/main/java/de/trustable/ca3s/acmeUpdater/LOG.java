package de.trustable.ca3s.acmeUpdater;

public class LOG {

	public static void error(final String msg) {
		System.err.println(msg);
	}
	public static void error(final String msg, final Throwable th) {
		System.err.println(msg);
		th.printStackTrace();
	}
	public static void debug(final String msg) {
		System.out.println(msg);
	}
}
