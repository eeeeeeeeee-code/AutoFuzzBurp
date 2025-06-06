package AutoBurp.bypass.beens;

import java.util.Arrays;

public record TLSNegotiation(String[] protocols, String[] ciphers) {
    public TLSNegotiation {
    }

    @Override
    public String toString() {
        return "TLSNegotiation{" +
                "protocols=" + Arrays.toString(protocols) +
                ", ciphers=" + Arrays.toString(ciphers) +
                '}';
    }
}
