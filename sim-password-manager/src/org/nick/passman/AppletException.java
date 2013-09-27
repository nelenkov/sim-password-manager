package org.nick.passman;

public class AppletException extends RuntimeException {

    private static final long serialVersionUID = 4147940124038306615L;

    public AppletException(String message) {
        super(message);
    }

    public AppletException(short sw) {
        super("SW: " + String.format("%02X", sw));
    }
}
