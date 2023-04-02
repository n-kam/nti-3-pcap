import lombok.extern.slf4j.Slf4j;
import org.pcap4j.core.PacketListener;
import org.pcap4j.core.PcapPacket;

import java.util.Optional;

@Slf4j
public class SvPacketListener implements PacketListener {

    int measPerPeriod;
    double frequency;
    double iSetPoint;
    double period;

    int packetCounter = 0;
    int faultStartIndex = 0;
    int faultEndIndex = 0;
    SvDecoder svDecoder = new SvDecoder();

    RMSFilter iaRmsFilter;
    RMSFilter ibRmsFilter;
    RMSFilter icRmsFilter;
    RMSFilter inRmsFilter;
    RMSFilter uaRmsFilter;
    RMSFilter ubRmsFilter;
    RMSFilter ucRmsFilter;
    RMSFilter unRmsFilter;

    public SvPacketListener(int measPerPeriod, double frequency, double iSetPoint) {
        this.measPerPeriod = measPerPeriod;
        this.frequency = frequency;
        this.iSetPoint = iSetPoint;
        this.period = 1 / frequency;

        this.iaRmsFilter = new RMSFilter(measPerPeriod);
        this.ibRmsFilter = new RMSFilter(measPerPeriod);
        this.icRmsFilter = new RMSFilter(measPerPeriod);
        this.inRmsFilter = new RMSFilter(measPerPeriod);
        this.uaRmsFilter = new RMSFilter(measPerPeriod);
        this.ubRmsFilter = new RMSFilter(measPerPeriod);
        this.ucRmsFilter = new RMSFilter(measPerPeriod);
        this.unRmsFilter = new RMSFilter(measPerPeriod);
    }

    String faultType = "";
    boolean aIsInFault;
    boolean bIsInFault;
    boolean cIsInFault;
    double Ia;
    double Ib;
    double Ic;
    double In;
    double Ua;
    double Ub;
    double Uc;
    double Un;
    double IaNorm = -1;
    double IbNorm = -1;
    double IcNorm = -1;
    double InNorm = -1;
    double UaNorm = -1;
    double UbNorm = -1;
    double UcNorm = -1;
    double UnNorm = -1;
    double IaFault = -1;
    double IbFault = -1;
    double IcFault = -1;
    double InFault = -1;
    double UaFault = -1;
    double UbFault = -1;
    double UcFault = -1;
    double UnFault = -1;

    int packetCounterPrev = packetCounter;

    // A hack to account for cases when fault lasts to the end of pcap file
    Thread timeoutOutput = new Thread(() -> {

        boolean interrupted = false;

        while ((packetCounter != packetCounterPrev) | (packetCounter == 0)) {
            packetCounterPrev = packetCounter;
            try {
                Thread.sleep(1000);
            } catch (InterruptedException e) {
                interrupted = true;
                log.debug("Timeout was interrupted");
            }
        }

        if (!interrupted) {
            log.warn("Outputting by timeout");
            faultEndIndex = packetCounter;
            log.info("Fault currents: Ia={}mA, Ib={}mA, Ic={}mA, In={}mA", IaFault, IbFault, IcFault, InFault);
            log.info("Fault voltages: Ua={}V, Ub={}V, Uc={}V, Un={}V", UaFault, UbFault, UcFault, UnFault);
            log.info("Fault duration: over {}s", ((double) (faultEndIndex - faultStartIndex) / measPerPeriod) * period);
            log.info("Fault type: {}", faultType);
            System.exit(0);
        }

    });


    @Override
    public void gotPacket(PcapPacket pcapPacket) {

        if (timeoutOutput.getState().equals(Thread.State.NEW)) timeoutOutput.start();

        Optional<SvPacket> svPacket = svDecoder.decode(pcapPacket);

        if (svPacket.isPresent()) {
            packetCounter += 1;
            SvPacket.Dataset dataSet = svPacket.get().getDataset();

            Ia = iaRmsFilter.rmsValue(dataSet.getInstIa());
            Ib = ibRmsFilter.rmsValue(dataSet.getInstIb());
            Ic = icRmsFilter.rmsValue(dataSet.getInstIc());
            In = inRmsFilter.rmsValue(dataSet.getInstIn());
            Ua = uaRmsFilter.rmsValue(dataSet.getInstUa());
            Ub = ubRmsFilter.rmsValue(dataSet.getInstUb());
            Uc = ucRmsFilter.rmsValue(dataSet.getInstUc());
            Un = unRmsFilter.rmsValue(dataSet.getInstUn());


            // Save normal currents and voltages
            if (packetCounter == measPerPeriod) {
                IaNorm = Ia;
                IbNorm = Ib;
                IcNorm = Ic;
                InNorm = In;
                UaNorm = Ua;
                UbNorm = Ub;
                UcNorm = Uc;
                UnNorm = Un;
                log.info("Normal currents: Ia={}mA, Ib={}mA, Ic={}mA, In={}mA", IaNorm, IbNorm, IcNorm, InNorm);
                log.info("Normal voltages: Ua={}V, Ub={}V, Uc={}V, Un={}V", UaNorm, UbNorm, UcNorm, UnNorm);
            }


            // If there was no fault earlier, but there is now, save current measurement index as fault start
            if ((faultStartIndex == 0) & (aIsInFault | bIsInFault | cIsInFault)) {
                faultStartIndex = packetCounter;
                log.debug("fault start index: {}", faultStartIndex);
            }


            // Which phases are currently in fault
            if (packetCounter > measPerPeriod) {
                aIsInFault = Ia > iSetPoint * IaNorm;
                bIsInFault = Ib > iSetPoint * IbNorm;
                cIsInFault = Ic > iSetPoint * IcNorm;
            }


            // Save which phases WERE ever in fault
            if (aIsInFault & !faultType.contains("A")) faultType += "A";
            if (bIsInFault & !faultType.contains("B")) faultType += "B";
            if (cIsInFault & !faultType.contains("C")) faultType += "C";


            // Save fault currents and voltages
            if ((Ia > IaFault) | (Ib > IbFault) | (Ic > IcFault)) {
                IaFault = Ia;
                IbFault = Ib;
                IcFault = Ic;
                InFault = In;
                UaFault = Ua;
                UbFault = Ub;
                UcFault = Uc;
                UnFault = Un;
            }


            // Debug output at every period
            if (packetCounter % measPerPeriod == 0) {
                log.debug("{}: Ia: {}, Ib: {}, Ic:{}, In:{}, Ua:{}, Ub:{}, Uc:{}, Un:{}", packetCounter, Ia, Ib, Ic, In, Ua, Ub, Uc, Un);
                log.debug("faultType: {}", faultType);
            }


            // If there was a fault earlier, but now there isn't, save current measurement index as fault end
            if ((faultStartIndex != 0) & (faultEndIndex == 0) & !(aIsInFault | bIsInFault | cIsInFault)) {
                timeoutOutput.interrupt();
                faultEndIndex = packetCounter;
                log.debug("fault end index: {}", faultEndIndex);
                log.info("Fault currents: Ia={}mA, Ib={}mA, Ic={}mA, In={}mA", IaFault, IbFault, IcFault, InFault);
                log.info("Fault voltages: Ua={}V, Ub={}V, Uc={}V, Un={}V", UaFault, UbFault, UcFault, UnFault);
                log.info("Fault duration: {}s", ((double) (faultEndIndex - faultStartIndex) / measPerPeriod) * period);
                log.info("Fault type: {}", faultType);
                System.exit(0);
            }
        }
    }
}
