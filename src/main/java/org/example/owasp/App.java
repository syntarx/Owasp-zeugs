package org.example.owasp;

public class App {
    public static void main(String[] args) {
        System.out.println("OWASP A6 - Unsichere Komponenten und Bibliotheken Projekt");

        // Beispiel: Unsichere Komponente verwenden
        UnsichereKomponente unsichereKomponente = new UnsichereKomponente();
        unsichereKomponente.unsichererAufruf();
    }
}
