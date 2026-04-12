package org.example.model;

import java.io.Serializable;
import java.util.List;

/**
 * Reprezentuje pojedynczy rekord ataku z pliku CSV.
 */
public class AttackRecord implements Serializable {

    public String sourceIp;        // IP atakującego (bez /32)
    public String rawPayload;      // surowy data payload (hex + ascii)
    public String decodedPayload;  // zdekodowany tekst ASCII z payloadu
    public String attackType;      // klasyfikacja ataku
    public List<String> extractedUrls;   // URL-e z payloadu
    public List<String> extractedIps;    // IP z payloadu (C2 serwery)
    public String malwareFamily;   // nazwa malware (np. Mirai, Mozi)
    public String rawExtracted;    // trzecia kolumna z CSV (gotowe IP/URL)

    public AttackRecord() {}
}
