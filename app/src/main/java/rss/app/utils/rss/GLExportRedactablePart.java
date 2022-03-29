package rss.app.utils.rss;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GLRSSPublicKey;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GLRSSSignatureOutput;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GSRSSPublicKey;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;
import org.bouncycastle.asn1.*;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Random;
import java.util.Set;

public class GLExportRedactablePart {
    private GLRSSSignatureOutput glrssSignatureOutput;
    private PublicKey dsigKey;
    private PublicKey accKey;
    private byte[] gsAccumulator;
    private byte[] gsDsigValue;
    private List<GLRSSSignatureOutput.GLRSSSignedPart> parts;
    private int maxNbWitnesses;

    private ASN1EncodableVector processedKeysDssAcc;

    public GLExportRedactablePart(GLRSSSignatureOutput glrssSignatureOutput, PublicKey glrssPublicKey) {
        this.glrssSignatureOutput = glrssSignatureOutput;
        /**
         * get the public keys of the set rss and accumulator
         */
        GSRSSPublicKey gsrssPublicKey = (GSRSSPublicKey) ((GLRSSPublicKey) glrssPublicKey).getGsrssKey();
        parts = glrssSignatureOutput.getParts();
        dsigKey = gsrssPublicKey.getDSigKey();
        accKey  = ((GLRSSPublicKey) glrssPublicKey).getAccumulatorKey();

        /** returns the maximum number of witnesses in this set of parts */
        maxNbWitnesses = parts.get(parts.size() - 1).getWitnesses().size();

        gsAccumulator = glrssSignatureOutput.getGsAccumulator();
        gsDsigValue   = glrssSignatureOutput.getGsDsigValue();

        processedKeysDssAcc = processKeysDssAcc();
    }


    /**
     * encoding what's in the parts but forgetting the rest
     * @return
     */
    public ASN1Sequence toDERSequence (GLRSSSignatureOutput.GLRSSSignedPart part) {

        ASN1EncodableVector vectGeneralPart = new ASN1EncodableVector();
        vectGeneralPart.add(new DERBitString(part.getMessagePart()));
        vectGeneralPart.add(new DERBitString(part.getAccumulatorValue()));
        vectGeneralPart.add(new DERBitString(part.getRandomValue()));
        vectGeneralPart.add(new DERBitString(part.getGsProof()));

        DERSequence v1 = new DERSequence(vectGeneralPart);

        ASN1EncodableVector witnessesVector = new ASN1EncodableVector();
        int i = 0;
        for (ByteArray witness : part.getWitnesses()) {
            witnessesVector.add(new DERBitString(witness.getArray()));
            i++;
        }

        int witnessSize = part.getWitnesses().get(0).getArray().length;

        byte[] fakeWitness = new byte[witnessSize];
        /**
         * the original position in the document should be omitted because it will
         * provide info about possible other redacted parts
         */
        if(i < maxNbWitnesses) {
            for(; i < maxNbWitnesses; i++) {
                new Random().nextBytes(fakeWitness);
                witnessesVector.add(new DERBitString(fakeWitness));
            }
        }

        DERSequence v2 = new DERSequence(witnessesVector);

        ASN1EncodableVector vectorPart = new ASN1EncodableVector();
        vectorPart.add(v1);
        vectorPart.add(v2);

        return new DERSequence(vectorPart);
    }

    /**
     * process the public keys of gsRSS and accumulator
     * I believe they're both RSA, which is freaking weird -> no FSS!!!
     */
    public ASN1EncodableVector processKeysDssAcc() {
        ASN1EncodableVector keyVector = new ASN1EncodableVector(2);
        DERSequence dsigKeySequence = new DERSequence(new DERBitString(dsigKey.getEncoded()));
        DERSequence accKeySequence  = new DERSequence(new DERBitString(accKey.getEncoded()));
        keyVector.add(dsigKeySequence);
        keyVector.add(accKeySequence);

        DERSequence keySequence = new DERSequence(keyVector);

        ASN1EncodableVector signatureVector = new ASN1EncodableVector(2);
        DERSequence gsDsign = new DERSequence(new DERBitString(gsDsigValue));
        DERSequence gsAcc   = new DERSequence(new DERBitString(gsAccumulator));
        signatureVector.add(gsDsign);
        signatureVector.add(gsAcc);

        DERSequence signSequence = new DERSequence(signatureVector);


        ASN1EncodableVector vector = new ASN1EncodableVector(2);
        vector.add(keySequence);
        vector.add(signSequence);


        return vector;
    }

    public byte[] getEncoded() throws IOException {
        ASN1EncodableVector finalVector = new ASN1EncodableVector(glrssSignatureOutput.getParts().size());

        for(GLRSSSignatureOutput.GLRSSSignedPart part : glrssSignatureOutput.getParts()){
            ASN1EncodableVector partVector = new ASN1EncodableVector(3);

            partVector.add(new DERSequence(processedKeysDssAcc));
            partVector.add(toDERSequence(part));
            partVector.add(/** @todo add all removed wintnesses */);

            finalVector.add(new DERSequence(partVector));
        }
        return (new DERSequence(finalVector)).getEncoded();
    }

    public void exportParts() throws IOException {
        ASN1EncodableVector partVector;
        byte[] export;
        String name;
        File   newFile;
        FileOutputStream fileOutputStream;

        for(GLRSSSignatureOutput.GLRSSSignedPart part : parts) {
            partVector = new ASN1EncodableVector(2);

            partVector.add(new DERSequence(processedKeysDssAcc));
            partVector.add(toDERSequence(part));

            export = (new DERSequence(partVector)).getEncoded();
            name = Base64.getEncoder().encodeToString(part.getRandomValue());
            newFile = new File("app/testdata/part-" + name  + ".sig");
            System.out.println(name);
            newFile.createNewFile();

            fileOutputStream = new FileOutputStream(newFile);
            fileOutputStream.write(export);
            fileOutputStream.close();
        }
    }

}
