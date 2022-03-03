package rss.app;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GLRSSPublicKey;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GLRSSSignatureOutput;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GSRSSPublicKey;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;
import org.bouncycastle.asn1.*;

import java.io.IOException;
import java.security.PublicKey;
import java.util.List;

public class GLExportSignature {
    private GLRSSSignatureOutput glrssSignatureOutput;
    private PublicKey dsigKey;
    private PublicKey accKey;

    GLExportSignature (GLRSSSignatureOutput glrssSignatureOutput, GLRSSPublicKey glrssPublicKey) {
        this.glrssSignatureOutput = glrssSignatureOutput;
        /**
         * get the public keys of the set rss and accumulator
         */
        GSRSSPublicKey gsrssPublicKey = glrssPublicKey.getGsrssKey();
        dsigKey = gsrssPublicKey.getDSigKey();
        accKey  = gsrssPublicKey.getAccumulatorKey();
    }

    /**
     * encoding what's in the parts but forgetting the rest
     * @return
     */
    public ASN1Sequence toDERSequence () {
        List<GLRSSSignatureOutput.GLRSSSignedPart> parts = glrssSignatureOutput.getParts();
        /**
         * prepare to encode as ASN.1
         */
        ASN1EncodableVector vector = new ASN1EncodableVector(parts.size());

        for (GLRSSSignatureOutput.GLRSSSignedPart part : parts) {

            vector.add(new DERBitString(part.getAccumulatorValue()));
            vector.add(new DERBitString(part.getRandomValue()));
            vector.add(new DERBitString(part.getGsProof()));
            ASN1EncodableVector witnessesVector = new ASN1EncodableVector(part.getWitnesses().size());

            for (ByteArray witness : part.getWitnesses()) {
                witnessesVector.add(new DERBitString(witness.getArray()));
            }
            vector.add((ASN1Encodable) witnessesVector);
        }

        return new DERSequence(vector);
    }

    public byte[] getEncoded () throws IOException {
        ASN1Sequence sequence = toDERSequence();
        return sequence.getEncoded();
    }

    /**
     * process the public keys of gsRSS and accumulator
     * I believe they're both RSA, which is freaking weird -> no FSS!!!
     */
    public void processKeys () {

    }

}
