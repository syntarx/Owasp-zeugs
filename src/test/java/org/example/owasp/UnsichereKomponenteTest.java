package org.example.owasp;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class UnsichereKomponenteTest {
    @Test
    public void testUnsichererAufruf() {
        UnsichereKomponente unsichereKomponente = new UnsichereKomponente();
        String result = unsichereKomponente.getUserRole();
        assertEquals("admin", result);
    }
}
