package rss.app;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GLRSSPublicKey;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GLRSSSignatureOutput;

import java.security.PublicKey;
import java.security.SignatureException;
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
    private GLRSSPublicKey publicKey;
    private byte[] setSignature;
    private byte[] setAcc;
    private int numberOfParts = 0;

    GLRSSSignatureExtractor (GLRSSSignatureOutput signatureOutput, PublicKey publicKey) throws SignatureException {
        randomValues   = getRandomValues(signatureOutput);
        accumulatorValues = getAccumulatorValues(signatureOutput);
        listWitnesses  = getListWitnesses(signatureOutput);

        this.publicKey = (GLRSSPublicKey) publicKey;

        setSignature = signatureOutput.getGsDsigValue();
        setSignature = Arrays.copyOf(setSignature, setSignature.length);

        setAcc       = signatureOutput.getGsAccumulator();
        setAcc       = Arrays.copyOf(setAcc, setAcc.length);
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
            numberOfParts++;
        }
        return randomValues;
    }

    /**
     * returns the accumulator values in THE ORDER THEY WHERE ADDED
     * @return
     */
    public ArrayList<byte[]> getAccumulatorValues(GLRSSSignatureOutput signatureOutput) throws SignatureException {
        ArrayList<byte[]> accumulatorValues = new ArrayList<>();
        int numberOfAccumulators = 0;
        for (GLRSSSignatureOutput.GLRSSSignedPart part : signatureOutput.getParts()){
            byte[] accLocal = part.getAccumulatorValue();
            accumulatorValues.add(Arrays.copyOf(accLocal, accLocal.length));
            numberOfAccumulators++;
        }
        if(numberOfAccumulators != numberOfParts){
            throw new SignatureException("Parsed the wrong number of parts");
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
