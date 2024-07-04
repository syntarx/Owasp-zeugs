package org.example.owasp;

public class UnsichereKomponente {
    public void unsichererAufruf() {
        // Beispiel: Unsichere Funktion mit bekannten Schwachstellen
        String userRole = getUserRole(); // Hypothetische Funktion, die Sicherheitslücken hat
        System.out.println("User role: " + userRole);
    }

    String getUserRole() {
        // Simulierter unsicherer Code - sollte sicherer implementiert werden
        return "admin";
    }
}
