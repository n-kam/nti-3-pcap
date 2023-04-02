import lombok.extern.slf4j.Slf4j;

@Slf4j
public class Main {
    public static void main(String[] args) {
        EthernetListener ethernetListener = new EthernetListener();
        ethernetListener.setNicName("enp1s0");
        ethernetListener.addListener(new SvPacketListener(80, 50, 2));
        ethernetListener.start();
    }

}