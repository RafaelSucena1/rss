package rss.app;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.Identifier;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.WPProvider;
import org.junit.Before;

import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.List;

public class GLImportRedactablePart {
    private byte[][] message = {
            "test1".getBytes(),
            "test2".getBytes(),
            "test3".getBytes(),
            "test4".getBytes(),
            "test5".getBytes(),
    };

    private PublicKey publicKey;
    private RedactableSignature rss;
    private SignatureOutput firstSignature;
    List<Identifier> rssIdentifiers = new ArrayList<Identifier>();


    static {
        Security.insertProviderAt(new WPProvider(), 0);
    }

    @Before
    public void initialize() throws Exception {
        KeyPairGenerator glRssGenerator = KeyPairGenerator.getInstance("GLRSSwithRSAandBPA");
        KeyPair glRssKeyPair = glRssGenerator.generateKeyPair();
        publicKey = glRssKeyPair.getPublic();
        rss = RedactableSignature.getInstance("GLRSSwithRSAandBPA");
        rss.initSign(glRssKeyPair);
        int i = 1;
        for (byte[] chunk : message) {
            rssIdentifiers.add(rss.addPart(chunk, (i % 2 == 0)));
            i++;
        }
    }



}
