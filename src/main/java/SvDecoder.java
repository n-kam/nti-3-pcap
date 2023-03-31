import org.pcap4j.core.PcapPacket;

import java.util.Optional;

public class SvDecoder {

    private static final int datasetSize = 64;


    public Optional<SvPacket> decode(PcapPacket packet) {
        byte[] data = packet.getRawData();
        int length = data.length;
        SvPacket result = new SvPacket();
        result.setMacDst(byteArrayToMac(data, 0));
        result.setMacSrc(byteArrayToMac(data, 6));
        result.getDataset().setInstIa(byteArrayToInt(data, length - datasetSize)/100.0);
        return Optional.of(result);
    }

    public static String byteArrayToMac(byte[] b, int offset) {
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
                b[offset],
                b[offset + 1],
                b[offset + 2],
                b[offset + 3],
                b[offset + 4],
                b[offset + 5]);
    }

    public static int byteArrayToInt(byte[] b, int offset) {
        return b[3 + offset] & 0xFF | (b[2 + offset] & 0xFF) << 8 | (b[1 + offset] & 0xFF) << 16 | (b[offset] & 0xFF) << 24;
    }
}
