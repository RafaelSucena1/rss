package rss.app.utils.rss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.Accumulator;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.AccumulatorException;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.*;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.*;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Enumeration;

public class GLImportSignature {
    private ASN1Sequence mainSequence;
    private PublicKey accPublicKey;
    private Accumulator gsAccBP;
    private GLRSSSignatureOutput.Builder builder;
    private byte[] gsSignature;
    public PublicKey generatedPublic;
    private SignatureOutput signatureOutput;
    private Accumulator posAccumulator;


    public GLImportSignature(File signatureFile, SignatureOutput signatureOutput) throws Exception {
        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(FileUtils.readFileToByteArray(signatureFile));
        ASN1InputStream asnInputStream = new ASN1InputStream(byteArrayInputStream);

        this.signatureOutput = signatureOutput;
        posAccumulator = Accumulator.getInstance("BPA");

        ASN1Primitive mainASN1Object =  asnInputStream.readObject();
        mainSequence = ASN1Sequence.getInstance(mainASN1Object);

        gsAccBP = Accumulator.getInstance("BPA");
        handleGeneralKeys();
        builder = handleParts();
    }

    public PublicKey getPublicKey(){
        GSRSSPublicKey gsrssPublicKey = new GSRSSPublicKey("GSRSSwithRSAandBPA",this.generatedPublic, this.accPublicKey);
        BPPublicKey    accKey         = (BPPublicKey) accPublicKey;
        GLRSSPublicKey glrssPublicKey = new GLRSSPublicKey("GLRSSwithRSAandBPA",(PublicKey) gsrssPublicKey,(PublicKey) accKey);

        return glrssPublicKey;
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
        generatedPublic = kf.generatePublic(new X509EncodedKeySpec(pkBytes));

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
        accPublicKey = mainAccKeyPair.getPublic();
        gsAccBP.initWitness(mainAccKeyPair);

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
        gsAccBP.initVerify(accPublicKey);
        gsAccBP.restoreVerify(accBitString.getBytes());

    }

    /**
     * generates the BP Keypair for the accumulator
     * @param bytes
     * @return
     */
    public KeyPair generateBPKeyFromBytes (byte[] bytes) {
        BigInteger bigInteger = new BigInteger(bytes);
        BPPublicKey bpPublicKey   = new BPPublicKey(bigInteger);
        BPPrivateKey bpPrivateKey = new BPPrivateKey();
        return new KeyPair(bpPublicKey, bpPrivateKey);
    }


    public GLRSSSignatureOutput.Builder handleParts () throws Exception {
        ASN1Sequence partsSequence = (ASN1Sequence) mainSequence.getObjectAt(1);
        if (partsSequence == null) {
            throw new Exception("There are no parts presented");
        }


        GLRSSSignatureOutput.Builder builder = new GLRSSSignatureOutput.Builder(partsSequence.size());
        Enumeration partSequences = partsSequence.getObjects();
        ASN1Sequence partSequence;
        int i = 0;
        do {
            partSequence  = (ASN1Sequence) partSequences.nextElement();

            ASN1Sequence accRandProofSequence = (ASN1Sequence) partSequence.getObjectAt(0);
            /** if the i'th part message */
            byte[] message = ((DERBitString) accRandProofSequence.getObjectAt(0)).getBytes();
            /** the i'th acccumulator value */
            byte[] accumulatorValue = ((DERBitString) accRandProofSequence.getObjectAt(1)).getBytes();
            /** the i'th random value */
            byte[] randomValue      = ((DERBitString) accRandProofSequence.getObjectAt(2)).getBytes();
            /** the i'th witness */
            byte[] gsWitness        = ((DERBitString) accRandProofSequence.getObjectAt(3)).getBytes();


            /* the witness array for the part */
            ASN1Sequence witnessSequence  = (ASN1Sequence) partSequence.getObjectAt(1);
            Enumeration  witnesses        = witnessSequence.getObjects();
            DERBitString witnessBitString;
            boolean stillValid;
            do {
                witnessBitString = (DERBitString) witnesses.nextElement();
                builder.addWittness(i, witnessBitString.getBytes());

            } while (witnesses.hasMoreElements());


            builder.setRedactable(i, true)
                    .setRandomValue(i, randomValue)
                    .setAccValue(i, accumulatorValue)
                    .setMessagePart(i, message)
                    .setGSProof(i, gsWitness);

            i++;
        } while (partSequences.hasMoreElements());

        return builder;
    }

    /**
     * provide the array of strings and
     * get a fully prepared SignatureOutput for linear documents
     * @param messages
     * @return
     */
    public GLRSSSignatureOutput getSignatureOutput(byte[][] messages) throws AccumulatorException {
        /**
         * set the GsDss -> the RSA signature for the non redactable parts
         * set the main accumultor
         */
        GSRSSSignatureOutput.Builder gsBuilder = new GSRSSSignatureOutput.Builder();
        gsBuilder.setDSigValue(gsSignature);
        gsBuilder.setAccumulatorValue(gsAccBP.getAccumulatorValue());
        int i = 0;
        for (byte[] message : messages) {
            builder.setMessagePart(i, message);
            gsBuilder.addSignedPart(builder.getConcat(i), builder.getGsProof(i), builder.getIsRedactable(i));
            i++;
        }
        GSRSSSignatureOutput gsrssSignatureOutput = gsBuilder.build();

        builder.embedGSOutput(gsrssSignatureOutput);

        return builder.build();
    }

    /**
     * helper function : concatenates all as byte[]
     * @param messagePart
     * @param accumulatorValue
     * @param randomValue
     * @return
     */
    static byte[] concat(byte[] messagePart, byte[] accumulatorValue, byte[] randomValue) {
        return new ByteArray(messagePart).concat(accumulatorValue).concat(randomValue).getArray();
    }
}
