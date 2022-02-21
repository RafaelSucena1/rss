package rss.app;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GLRSSSignatureOutput;

import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;

/**
 * @author Rafael Sucena
 * this class copies the data from the SignatureOutput for linear documents
 * and stores it
 * @todo encode it and save it in a file
 */
class GLRSSSignatureExtractor {

    private ArrayList<byte[]> randomValues;
    private ArrayList<byte[]> accumulatorValues;
    private ArrayList<ArrayList<byte[]>> listWitnesses;
    private PublicKey publicKey;
    private byte[] dSignature;

    GLRSSSignatureExtractor (GLRSSSignatureOutput signatureOutput, PublicKey publicKey) {
        randomValues   = getRandomValues(signatureOutput);
        accumulatorValues = getAccumulatorValues(signatureOutput);
        listWitnesses  = getListWitnesses(signatureOutput);

        this.publicKey = publicKey;

        byte[] dSignatureLocal     = signatureOutput.getGsDsigValue();
        dSignature = Arrays.copyOf(dSignatureLocal, dSignatureLocal.length);
    }

    /**
     * returns the random values in THE ORDER THEY WHERE ADDED
     * @return
     */
    public ArrayList<byte[]> getRandomValues(GLRSSSignatureOutput signatureOutput){
        ArrayList<byte[]> randomValues = new ArrayList<>();

        for (GLRSSSignatureOutput.GLRSSSignedPart part : signatureOutput.getParts()){
            byte[] randomLocal = part.getRandomValue();
            randomValues.add(Arrays.copyOf(randomLocal, randomLocal.length));
        }
        return randomValues;
    }

    /**
     * returns the accumulator values in THE ORDER THEY WHERE ADDED
     * @return
     */
    public ArrayList<byte[]> getAccumulatorValues(GLRSSSignatureOutput signatureOutput){
        ArrayList<byte[]> accumulatorValues = new ArrayList<>();

        for (GLRSSSignatureOutput.GLRSSSignedPart part : signatureOutput.getParts()){
            byte[] accLocal = part.getAccumulatorValue();
            accumulatorValues.add(Arrays.copyOf(accLocal, accLocal.length));
        }
        return accumulatorValues;
    }

    /**
     * returns a list of the witnesses for each part
     * IN THE ORDER THEY WHERE ADDED
     * @return
     */
    public ArrayList<ArrayList<byte[]>> getListWitnesses(GLRSSSignatureOutput signatureOutput){
        ArrayList<ArrayList<byte[]>> witnesses = new ArrayList<>();

        for (GLRSSSignatureOutput.GLRSSSignedPart part : signatureOutput.getParts()){
            ArrayList<byte[]> witnessesForPart = new ArrayList<>();
            for(ByteArray witness : part.getWitnesses()){
                byte[] witnessLocal = witness.getArray();
                witnessesForPart.add(Arrays.copyOf(witnessLocal, witnessLocal.length));
            }
            witnesses.add(witnessesForPart);
        }
        return witnesses;
    }
}
