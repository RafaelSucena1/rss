package rss.app;

import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GLRSSSignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.grss.GSRSSSignatureOutput;
import de.unipassau.wolfgangpopp.xmlrss.wpprovider.utils.ByteArray;

import javax.xml.crypto.Data;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.util.Map;

public class SetSignatureExtractor {
    Map<ByteArray, byte[]> parts;
    private byte[] dSigValue;
    private byte[] accumulatorValue;
    private ByteBuffer dSigSize;
    private ByteBuffer accSize;

    SetSignatureExtractor (GLRSSSignatureOutput glRssSignatureOutput) {
        GSRSSSignatureOutput gsRssSignatureOutput = glRssSignatureOutput.extractGSOutput();
        parts = gsRssSignatureOutput.getParts();
        dSigValue = gsRssSignatureOutput.getDSigValue();
        accumulatorValue = gsRssSignatureOutput.getAccumulatorValue();
    }

    public void writeByteSizeOfVariables(ByteBuffer buffer, FileChannel channel) throws IOException {

        buffer.putInt(dSigValue.length);
        channel.write(buffer);
        buffer.rewind();

        buffer.putInt(accumulatorValue.length);
        channel.write(buffer);
        buffer.rewind();

    }

    public void writeAll(FileChannel channel, ByteBuffer buffer) throws IOException {

        buffer = ByteBuffer.allocate(dSigValue.length).put(dSigValue);
        channel.write(buffer);
        buffer.rewind();

        buffer  = ByteBuffer.allocate(accumulatorValue.length).put(accumulatorValue);
        channel.write(buffer);
        buffer.rewind();

    }
}
