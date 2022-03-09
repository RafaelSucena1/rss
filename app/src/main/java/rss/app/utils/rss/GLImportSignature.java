package rss.app.utils.rss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.Accumulator;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.RedactableSignature;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.WPProvider;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.BPPrivateKey;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.BPPublicKey;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.*;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class GLImportSignature {
    private ASN1Sequence mainSequence;
    private ASN1Primitive generalKeysASN1Object;
    private ASN1Primitive partsASN1Object;

    private PublicKey accPublicKey;
    private PublicKey gsrssPublicKey;
    private final Accumulator mainAccBP;
    private RedactableSignature rss;
    private byte[] gsSignature;


    public GLImportSignature(File file) throws Exception {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(FileUtils.readFileToByteArray(file));
        ASN1InputStream asnInputStream = new ASN1InputStream(byteArrayInputStream);

        ASN1Primitive mainASN1Object =  asnInputStream.readObject();
        mainSequence = ASN1Sequence.getInstance(mainASN1Object);

        rss       = RedactableSignature.getInstance("GLRSSwithRSAandBPA");
        mainAccBP = Accumulator.getInstance("BPA");
        handleGeneralKeys();
        handleParts();
    }

    /**
     * handles the loading of the GS keys
     * will call the handling of the signatures
     * @throws Exception
     */
    public void handleGeneralKeys () throws Exception {
        ASN1Sequence keyAndDss = (ASN1Sequence) mainSequence.getObjectAt(0);
        if (keyAndDss == null) {
            throw new Exception("The file does not have enough data.");
        }
        ASN1Sequence publicKeys = (ASN1Sequence) keyAndDss.getObjectAt(0);
        /** main signature (used for non redactable parts) is RSA */
        DLSequence dSignSequence = (DLSequence) publicKeys.getObjectAt(0);
        if (dSignSequence == null) {
            throw new Exception("No public key Found");
        }

        DERBitString pkBitString = (DERBitString) dSignSequence.getObjects().nextElement();
        if (pkBitString == null) {
            throw new Exception("The file does not have enough data - DSS");
        }
        /** the DSS signature for the non redactable elements is RSA in GL */
        byte[] pkBytes = pkBitString.getBytes();
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PublicKey generatedPublic = kf.generatePublic(new X509EncodedKeySpec(pkBytes));

        /** get the key from main accumulator (SET/GS) */
        DLSequence accKeySequence = (DLSequence) publicKeys.getObjectAt(1);
        if (accKeySequence == null) {
            throw new Exception("No main accumulator Found");
        }

        DERBitString accBitString = (DERBitString) accKeySequence.getObjects().nextElement();
        if (accBitString == null) {
            throw new Exception("No accumulator bit string");
        }

        KeyPair mainAccKeyPair = generateBPKeyFromBytes(accBitString.getBytes());
        mainAccBP.initWitness(mainAccKeyPair);

        ASN1Sequence mainSignaturesNState = (ASN1Sequence) keyAndDss.getObjectAt(1);
        mainSignNState(mainSignaturesNState);
    }

    /**
     * handles the loading of the signatures of ADM :
     * that is: Dss and Acc_M status
     * @param mainSignaturesNState
     * @throws Exception
     */
    private void mainSignNState (ASN1Sequence mainSignaturesNState) throws Exception {
        /** the main Signature/ DSS / immutable through redaction */
        ASN1Sequence dssSequence = (ASN1Sequence) mainSignaturesNState.getObjectAt(0);
        if (dssSequence == null) {
            throw new Exception("No main signature found");
        }
        DERBitString dssBitString = (DERBitString) dssSequence.getObjects().nextElement();
        if (dssBitString == null) {
            throw new Exception("No DSS bit string");
        }
        gsSignature = dssBitString.getBytes();

        /** to update the main accumulator state (the inner value) */
        ASN1Sequence accSequence = (ASN1Sequence) mainSignaturesNState.getObjectAt(1);
        if (accSequence == null) {
            throw new Exception("No main acc. state found found");
        }
        DERBitString accBitString = (DERBitString) accSequence.getObjects().nextElement();
        if (accBitString == null) {
            throw new Exception("No main acc. bit string");
        }
        mainAccBP.initVerify(accPublicKey);
        mainAccBP.restoreVerify(accBitString.getBytes());

    }

    /**
     * generates the BP Keypair for the accumulator
     * @param bytes
     * @return
     */
    public KeyPair generateBPKeyFromBytes (byte[] bytes) {
        BigInteger bigInteger = new BigInteger(bytes);
        BPPublicKey bpPublicKey   = new BPPublicKey(bigInteger);
        accPublicKey = bpPublicKey;
        BPPrivateKey bpPrivateKey = new BPPrivateKey();
        return new KeyPair(bpPublicKey, bpPrivateKey);
    }


    public void handleParts () throws Exception {
        ASN1Sequence keyAndDss = (ASN1Sequence) mainSequence.getObjectAt(1);
        if (keyAndDss == null) {
            throw new Exception("There are no parts presented");
        }

        ASN1Sequence part



    }

}
