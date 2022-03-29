package rss.app.utils.rss.IORssExceptions;

import java.security.GeneralSecurityException;

public class RssImportPartException extends GeneralSecurityException {
    /**
     *
     */
    public RssImportPartException() {
        super();
    }

    /**
     *
     * @param message
     */
    public RssImportPartException(String message) {
        super(message);
    }

    /**
     *
     * @param message
     * @param cause
     */
    public RssImportPartException(String message, Throwable cause) {
        super(message, cause);
    }

    /**
     *
     * @param cause
     */
    public RssImportPartException(Throwable cause) {
        super(cause);
    }
}