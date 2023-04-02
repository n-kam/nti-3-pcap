import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.PcapPacket;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

@Slf4j
public class SvDecoder {

    private static final int datasetSize = 64;


    public Optional<SvPacket> decode(PcapPacket packet) {

        byte[] data = packet.getRawData();
        int length = data.length;

        SvPacket result = new SvPacket();

        result.setMacDst(byteArrayToMac(data, 0));
        result.setMacSrc(byteArrayToMac(data, 6));

        result.setPacketType(byteArrayToInt2(data, 12));
        result.setAppID((short) byteArrayToInt2(data, 14));
        result.setSvID(byteArrayToString(data, 34, 10));
        result.setSmpCnt((short) byteArrayToInt2(data, 45));
        result.setConfRef(byteArrayToInt4(data, 49));
        result.setSmpSynch(data[55]);

        int dataOffset = length - datasetSize;
        int valueSize = 4;

        result.getDataset().setInstIa(byteArrayToInt4(data, dataOffset + 0 * valueSize) / 100.0);
        result.getDataset().setQIa(byteArrayToInt4(data, dataOffset + 1 * valueSize));
        result.getDataset().setInstIb(byteArrayToInt4(data, dataOffset + 2 * valueSize) / 100.0);
        result.getDataset().setQIb(byteArrayToInt4(data, dataOffset + 3 * valueSize));
        result.getDataset().setInstIc(byteArrayToInt4(data, dataOffset + 4 * valueSize) / 100.0);
        result.getDataset().setQIc(byteArrayToInt4(data, dataOffset + 5 * valueSize));
        result.getDataset().setInstIn(byteArrayToInt4(data, dataOffset + 6 * valueSize) / 100.0);
        result.getDataset().setQIn(byteArrayToInt4(data, dataOffset + 7 * valueSize));

        result.getDataset().setInstUa(byteArrayToInt4(data, dataOffset + 8 * valueSize) / 1000.0);
        result.getDataset().setQUa(byteArrayToInt4(data, dataOffset + 9 * valueSize));
        result.getDataset().setInstUb(byteArrayToInt4(data, dataOffset + 10 * valueSize) / 1000.0);
        result.getDataset().setQUb(byteArrayToInt4(data, dataOffset + 11 * valueSize));
        result.getDataset().setInstUc(byteArrayToInt4(data, dataOffset + 12 * valueSize) / 1000.0);
        result.getDataset().setQUc(byteArrayToInt4(data, dataOffset + 13 * valueSize));
        result.getDataset().setInstUn(byteArrayToInt4(data, dataOffset + 14 * valueSize) / 1000.0);
        result.getDataset().setQUn(byteArrayToInt4(data, dataOffset + 15 * valueSize));

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

    public static int byteArrayToInt4(byte[] b, int offset) {
        return b[3 + offset] & 0xFF | (b[2 + offset] & 0xFF) << 8 | (b[1 + offset] & 0xFF) << 16 | (b[offset] & 0xFF) << 24;
    }

    public static int byteArrayToInt2(byte[] b, int offset) {
        return (b[1 + offset] & 0xFF) | (b[offset] & 0xFF) << 8;
    }

    public static String byteArrayToString(byte[] b, int offset, int length) {
        return new String(Arrays.copyOfRange(b, offset, offset + length - 1), StandardCharsets.UTF_8);
    }
}
