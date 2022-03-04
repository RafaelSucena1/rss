package rss.app;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;
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

    GLExportSignature (GLRSSSignatureOutput glrssSignatureOutput, PublicKey glrssPublicKey) {
        this.glrssSignatureOutput = glrssSignatureOutput;
        /**
         * get the public keys of the set rss and accumulator
         */
        GSRSSPublicKey gsrssPublicKey = (GSRSSPublicKey) ((GLRSSPublicKey) glrssPublicKey).getGsrssKey();
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
        ASN1EncodableVector mainVector = new ASN1EncodableVector(2);
        ASN1EncodableVector signaturesVector = processKeys();
        ASN1EncodableVector vector = new ASN1EncodableVector(parts.size());

        for (GLRSSSignatureOutput.GLRSSSignedPart part : parts) {

            ASN1EncodableVector vectGeneralPart = new ASN1EncodableVector();
            vectGeneralPart.add(new DERBitString(part.getAccumulatorValue()));
            vectGeneralPart.add(new DERBitString(part.getRandomValue()));
            vectGeneralPart.add(new DERBitString(part.getGsProof()));

            DERSequence v1 = new DERSequence(vectGeneralPart);

            ASN1EncodableVector witnessesVector = new ASN1EncodableVector();
            for (ByteArray witness : part.getWitnesses()) {
                witnessesVector.add(new DERBitString(witness.getArray()));
            }

            DERSequence v2 = new DERSequence(witnessesVector);

            ASN1EncodableVector vectorPart = new ASN1EncodableVector();
            vectorPart.add(v1);
            vectorPart.add(v2);

            vector.add(new DERSequence(vectorPart));

        }
        mainVector.add(new DERSequence(signaturesVector));
        mainVector.add(new DERSequence(vector));

        return new DERSequence(mainVector);
    }

    /**
     * process the public keys of gsRSS and accumulator
     * I believe they're both RSA, which is freaking weird -> no FSS!!!
     */
    public ASN1EncodableVector processKeys () {
        ASN1EncodableVector vector = new ASN1EncodableVector(2);
        vector.add(new DERBitString(dsigKey.getEncoded()));
        vector.add(new DERBitString(accKey.getEncoded()));
        return vector;
    }

    public byte[] getEncoded () throws IOException {
        ASN1Sequence sequence = toDERSequence();
        return sequence.getEncoded();
    }


}
