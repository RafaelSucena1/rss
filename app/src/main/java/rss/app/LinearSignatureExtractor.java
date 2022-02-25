package rss.app;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GLRSSSignatureOutput;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.PublicKey;
import java.util.Base64;
import java.util.List;
import java.util.Set;

public class LinearSignatureExtractor {
    private List<GLRSSSignatureOutput.GLRSSSignedPart> linearParts;
    private SetSignatureExtractor setSignatureExtractor;
    private File file;
    private PublicKey publicKey;
    private final int bufferSize = 16;


    LinearSignatureExtractor (SignatureOutput signatureOutput, PublicKey publicKey, String fileName) {
        GLRSSSignatureOutput glrssSignatureOutput = (GLRSSSignatureOutput) signatureOutput;
        file = new File(fileName + ".rss");

        this.publicKey = publicKey;
        linearParts = glrssSignatureOutput.getParts();
        setSignatureExtractor = new SetSignatureExtractor(glrssSignatureOutput);
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

    /**
     * writes the sizes of the types of data
     * @throws IOException
     */
    public void writeByteSizeOfVariables() throws IOException {
        if (file.delete()) {
            System.out.println("File existed, deleted: " + String.valueOf(file));
        } else {
            System.out.println("File did not exist: " + String.valueOf(file));
        }

        FileOutputStream fileOutputStream = new FileOutputStream(file, true);
        try {
            /** number of parts */
            fileOutputStream.write(linearParts.size());
            /** size of the accumulator for random numbers */
            fileOutputStream.write(linearParts.get(0).getAccumulatorValue().length);
            /** size of witnesses for random numbers */
            fileOutputStream.write(linearParts.get(0).getGsProof().length);

            /** size of random numbers */
            fileOutputStream.write(linearParts.get(0).getRandomValue().length);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }
        Base64.Encoder encoder = Base64.getEncoder();
        System.out.println(encoder.encodeToString(publicKey.getEncoded()));
byte[] x = publicKey.getEncoded();
int i = 1;
        /** size of the PublicKey *//*
        buffer.putInt(publicKey.getEncoded().length);
        System.out.println("Public key length: "+ publicKey.getEncoded().length);*/

/*        channel.write(buffer);
        buffer.rewind();*/
        //setSignatureExtractor.writeByteSizeOfVariables(buffer, channel); /** SetExtractor prepared 2 buffers */

        /** number of parts */
/*        buffer.putInt(linearParts.size());
        channel.write(buffer);
        buffer.rewind();*/

        /** size of the accumulator for random numbers *//*
        int x = 1;
        buffer.putInt(linearParts.get(0).getAccumulatorValue().length);
        System.out.println("Linear parts length: "+ linearParts.get(0).getAccumulatorValue().length);*/

/*        channel.write(buffer);
        buffer.rewind();*/

        /** size of witnesses for random numbers */
/*        buffer.putInt(linearParts.get(0).getGsProof().length);
        channel.write(buffer);
        buffer.rewind();*/

        /** size of random numbers */
/*        buffer.putInt(linearParts.get(0).getRandomValue().length);
        channel.write(buffer);
        buffer.rewind();

        channel.close();*/
        setPosixPermissions(file);
    }


    public void writeAll (FileChannel channel) throws IOException {
        ByteBuffer buffer;
        /** writting the public key */
        buffer = ByteBuffer.allocate(publicKey.getEncoded().length).
                put(publicKey.getEncoded());
        channel.write(buffer);

        setSignatureExtractor.writeAll(channel, buffer); /** SetExtractor prepared 2 buffers */

        /** number of parts */
        buffer = ByteBuffer.allocate(bufferSize).
                putInt(linearParts.size());
        channel.write(buffer);

        /** size of the accumulator for random numbers */
        buffer  = ByteBuffer.allocate(bufferSize).
                putInt(linearParts.get(0).getAccumulatorValue().length);
        channel.write(buffer);

        /** size of witnesses for random numbers */
        buffer  = ByteBuffer.allocate(bufferSize).
                putInt(linearParts.get(0).getGsProof().length);
        channel.write(buffer);

        /** size of random numbers */
        buffer  = ByteBuffer.allocate(bufferSize).
                putInt(linearParts.get(0).getRandomValue().length);
        channel.write(buffer);

    }

}
