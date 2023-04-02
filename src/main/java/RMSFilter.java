import lombok.extern.slf4j.Slf4j;

import java.util.ArrayList;
import java.util.List;

@Slf4j
public class RMSFilter {

    private int windowSize;

    public RMSFilter(int windowSize) {
        this.windowSize = windowSize;
    }

    private final List<Double> window = new ArrayList<>(windowSize);

    public double rmsValue(double x) {

        window.add(x);

        if (window.size() == windowSize + 1) {
            window.remove(0);
        }

        double nominator = 0;

        for (Double d : window) {
            nominator += Math.pow(d, 2);
        }

        return Math.sqrt(nominator / windowSize);
    }

}
