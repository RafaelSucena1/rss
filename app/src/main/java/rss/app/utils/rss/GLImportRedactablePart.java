package rss.app.utils.rss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.*;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.*;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.asn1.*;
import rss.app.utils.rss.IORssExceptions.RssImportPartException;

import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.List;

public class GLImportRedactablePart {
    private ASN1Sequence mainSequence;
    private PublicKey accPublicKey;
    private Accumulator gsAccBP;
    private GLRSSSignatureOutput.Builder builder;
    private byte[] gsSignature;
    public PublicKey generatedPublic;
    public GLRSSSignatureOutput signatureOutput;
    private Accumulator posAccumulator;

    public GLImportRedactablePart(File signatureFile, GLRSSSignatureOutput signatureOutput) throws Exception {
        this.signatureOutput = signatureOutput;

        ByteArrayInputStream byteArrayInputStream = new ByteArrayInputStream(FileUtils.readFileToByteArray(signatureFile));
        ASN1InputStream asnInputStream = new ASN1InputStream(byteArrayInputStream);

        ASN1Primitive mainASN1Object =  asnInputStream.readObject();
        mainSequence = ASN1Sequence.getInstance(mainASN1Object);


        posAccumulator = Accumulator.getInstance("BPA");

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

        List<GLRSSSignatureOutput.GLRSSSignedPart> parts = new ArrayList<GLRSSSignatureOutput.GLRSSSignedPart>(signatureOutput.getParts());

        GLRSSSignatureOutput.Builder builder = new GLRSSSignatureOutput.Builder(partsSequence.size());
        Enumeration partSequences = partsSequence.getObjects();

        /** we are assuming that we will import just one part */
        ASN1Sequence partSequence  = (ASN1Sequence) partSequences.nextElement();

        ASN1Sequence accRandProofSequence = (ASN1Sequence) partSequence.getObjectAt(0);
        /** get the message */
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
        byte[]       witness;


        byte[][] witnessesToInsert = new byte[witnessSequence.size()][];
        int insertIndex = 0;
        boolean beforePart = true;
        for(int i = 0; i < parts.size() && beforePart; i++){
            witness = ((DERBitString) witnesses.nextElement()).getBytes();
            beforePart = externalPartAfterIndex(i, witness, accumulatorValue);
            witnessesToInsert[i] = Arrays.copyOf(witness, witness.length);
            insertIndex++;
        }

        int index = 0;
        for(GLRSSSignatureOutput.GLRSSSignedPart part : parts) {
            if(index != insertIndex) {
                builder.setMessagePart(index,part.getMessagePart())
                        .setRedactable(index, part.isRedactable())
                        .setAccValue(index, part.getAccumulatorValue())
                        .setRandomValue(index, part.getRandomValue())
                        .setWitnesses(index, part.getWitnesses());
            } else {
                builder.addWittness(index, witnessesToInsert[index])
                        .setRedactable(index, true)
                        .setRandomValue(index, randomValue)
                        .setAccValue(index, accumulatorValue)
                        .setMessagePart(index, message)
                        .setGSProof(index, gsWitness);
            }

            index++;
        }

        return builder;
    }


    /**
     * returns true if all random values of given SignatureOutput
     * before the index i
     * are valid for the part we are trying to insert
     * @param signature
     * @param part
     * @return
     * @throws RedactableSignatureException
     */
    protected boolean externalPartAfterIndex(int i, byte[] witness, byte[] accumulatorValue) throws RedactableSignatureException, RssImportPartException {
        List<GLRSSSignatureOutput.GLRSSSignedPart> parts = signatureOutput.getParts();

        /** gvwIndex == greatest valid witness index */
        int gvwIndex = 0;

        try {
            boolean verify = true;
            GLRSSSignatureOutput.GLRSSSignedPart signedPart;
            posAccumulator.restoreVerify(accumulatorValue);

            for (; verify; gvwIndex++) {
                signedPart = parts.get(gvwIndex);

                byte[] randomValue = signedPart.getRandomValue();
                verify = posAccumulator.verify(witness, randomValue);
            }
        } catch (AccumulatorException e) {
            e.printStackTrace();
        }

        return gvwIndex > i;
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
}
