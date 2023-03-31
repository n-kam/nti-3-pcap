import java.util.Optional;

public class Main {
    public static void main(String[] args) {
        EthernetListener ethernetListener = new EthernetListener();
        ethernetListener.setNicName("enp1s0");

        SvDecoder svDecoder = new SvDecoder();

        ethernetListener.addListener(packet -> {
            Optional<SvPacket> svPacket = svDecoder.decode(packet);
            svPacket.ifPresent(System.out::println);
        });

        ethernetListener.start();
    }
}