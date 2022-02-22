package rss.app;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.SignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GLRSSSignatureOutput;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.Channels;
import java.nio.channels.FileChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFileAttributes;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.PublicKey;
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
        file = new File(fileName + ".sign");

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
        perms.add(PosixFilePermission.GROUP_EXECUTE);
        perms.add(PosixFilePermission.OTHERS_WRITE);
        perms.add(PosixFilePermission.OTHERS_READ);
        perms.add(PosixFilePermission.OTHERS_EXECUTE);
        Files.setPosixFilePermissions(path, perms);

        System.out.format("Permissions after:  %s%n",  PosixFilePermissions.toString(perms));

    }

    /**
     * writes the sizes of the types of data
     * @throws IOException
     */
    public void writeBytes() throws IOException {
        if (file.delete()) {
            System.out.println("File existed, deleted: " + String.valueOf(file));
        } else {
            System.out.println("File did not exist: " + String.valueOf(file));
        }

        FileOutputStream fileOutputStream = new FileOutputStream(file, true);
        FileChannel channel = fileOutputStream.getChannel();

        ByteBuffer buffer;
        /** size of the PublicKey */
        buffer = ByteBuffer.allocate(bufferSize).
                putInt(publicKey.getEncoded().length);
        channel.write(buffer);

        setSignatureExtractor.writeBytes(bufferSize, channel); /** SetExtractor prepared 2 buffers */

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

        channel.close();
        setPosixPermissions(file);
    }


    public void writeAll (FileChannel channel) throws IOException {
        ByteBuffer buffer;
        /** writting the public key */
        buffer = ByteBuffer.allocate(publicKey.getEncoded().length).
                put(publicKey.getEncoded());
        channel.write(buffer);

        setSignatureExtractor.writeAll(channel); /** SetExtractor prepared 2 buffers */

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
