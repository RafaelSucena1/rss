package rss.app;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GLRSSPublicKey;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GLRSSSignatureOutput;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GSRSSPublicKey;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;
import org.bouncycastle.asn1.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.PublicKey;
import java.util.List;
import java.util.Set;

public class GLExportSignature {
    private GLRSSSignatureOutput glrssSignatureOutput;
    private PublicKey dsigKey;
    private PublicKey accKey;
    private byte[] gsAccumulator;
    private byte[] gsDsigValue;

    GLExportSignature (GLRSSSignatureOutput glrssSignatureOutput, PublicKey glrssPublicKey) {
        this.glrssSignatureOutput = glrssSignatureOutput;
        /**
         * get the public keys of the set rss and accumulator
         */
        GSRSSPublicKey gsrssPublicKey = (GSRSSPublicKey) ((GLRSSPublicKey) glrssPublicKey).getGsrssKey();
        dsigKey = gsrssPublicKey.getDSigKey();
        accKey  = gsrssPublicKey.getAccumulatorKey();

        gsAccumulator = glrssSignatureOutput.getGsAccumulator();
        gsDsigValue   = glrssSignatureOutput.getGsDsigValue();
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

        return new DERSequence(vector);
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

    public byte[] getEncoded () throws IOException {
        ASN1EncodableVector finalVector = new ASN1EncodableVector(2);

        finalVector.add(new DERSequence(processKeysDssAcc()));
        finalVector.add(toDERSequence());

        return (new DERSequence(finalVector)).getEncoded();
    }

    public void setPosixPermissions (File file) throws IOException {
        Path path = Paths.get(String.valueOf(file));
        Set<PosixFilePermission> perms = Files.readAttributes(path, PosixFileAttributes.class).permissions();

        System.out.format("Permissions before: %s%n",  PosixFilePermissions.toString(perms));

        perms.add(PosixFilePermission.OWNER_WRITE);
        perms.add(PosixFilePermission.OWNER_READ);
        perms.add(PosixFilePermission.OWNER_EXECUTE);
        perms.add(PosixFilePermission.GROUP_WRITE);
        perms.add(PosixFilePermission.GROUP_READ);
        perms.add(PosixFilePermission.OTHERS_WRITE);
        perms.add(PosixFilePermission.OTHERS_READ);
        Files.setPosixFilePermissions(path, perms);

        System.out.format("Permissions after:  %s%n",  PosixFilePermissions.toString(perms));

    }

}
