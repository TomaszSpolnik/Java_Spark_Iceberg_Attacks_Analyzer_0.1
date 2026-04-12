package org.example.parser;

import org.example.model.AttackRecord;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.regex.*;

/**
 * Parser pliku CSV z atakami.
 *
 * Format pliku jest nieregularny:
 *   - kolumna 1: IP atakującego (opcjonalnie z /32)
 *   - kolumna 2: Data Payload (hex dump, wieloliniowy, w cudzysłowach)
 *   - kolumna 3: wyekstraktowane adresy (opcjonalnie)
 *
 * Parser ręcznie obsługuje wieloliniowe pola CSV w cudzysłowach.
 */
public class CsvParser {

    // Regex do wyciągania IP z tekstu
    private static final Pattern IP_PATTERN = Pattern.compile(
        "\\b((?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?))(?::\\d+)?\\b"
    );

    // Regex do wyciągania URL-i
    private static final Pattern URL_PATTERN = Pattern.compile(
        "https?://[^\\s;\"'\\\\]+"
    );

    // Regex do wyciągania ASCII z hex dump (prawa kolumna)
    private static final Pattern ASCII_PATTERN = Pattern.compile(
        "[0-9A-Fa-f]{2}(?:\\s+[0-9A-Fa-f]{2})*\\s{2,}(.{4,})"
    );

    public static List<AttackRecord> parse(String filePath) throws IOException {
        String content = Files.readString(Paths.get(filePath));
        List<AttackRecord> records = new ArrayList<>();

        // Ręczny parser CSV obsługujący wieloliniowe pola w cudzysłowach
        List<List<String>> rows = parseCsvManually(content);

        for (List<String> row : rows) {
            if (row.isEmpty() || row.get(0).isBlank()) continue;

            AttackRecord rec = new AttackRecord();

            // Kolumna 1: IP atakującego
            String ip = row.get(0).trim();
            ip = ip.replaceAll("/\\d+$", ""); // usuń /32
            if (!isValidIpOrHost(ip)) continue;
            rec.sourceIp = ip;

            // Kolumna 2: payload
            rec.rawPayload = row.size() > 1 ? row.get(1).trim() : "";

            // Kolumna 3: gotowe wyekstraktowane adresy
            rec.rawExtracted = row.size() > 2 ? row.get(2).trim() : "";

            // Dekoduj ASCII z hex dump
            rec.decodedPayload = extractAsciiFromDump(rec.rawPayload);

            // Wyciągnij URL-e i IP
            String searchText = rec.decodedPayload.isEmpty() ? rec.rawPayload : rec.decodedPayload;
            searchText += " " + rec.rawExtracted;

            rec.extractedUrls = extractUrls(searchText);
            rec.extractedIps  = extractIps(searchText);

            // Klasyfikuj atak
            rec.attackType    = classifyAttack(rec.rawPayload, rec.decodedPayload, rec.rawExtracted);
            rec.malwareFamily = detectMalwareFamily(rec.decodedPayload, rec.rawPayload);

            records.add(rec);
        }

        return records;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Ręczny parser CSV
    // ─────────────────────────────────────────────────────────────────────────

    private static List<List<String>> parseCsvManually(String content) {
        List<List<String>> rows = new ArrayList<>();
        List<String> currentRow = new ArrayList<>();
        StringBuilder currentField = new StringBuilder();
        boolean inQuotes = false;

        for (int i = 0; i < content.length(); i++) {
            char c = content.charAt(i);

            if (c == '"') {
                if (inQuotes && i + 1 < content.length() && content.charAt(i + 1) == '"') {
                    currentField.append('"');
                    i++;
                } else {
                    inQuotes = !inQuotes;
                }
            } else if (c == ',' && !inQuotes) {
                currentRow.add(currentField.toString());
                currentField = new StringBuilder();
            } else if ((c == '\n') && !inQuotes) {
                currentRow.add(currentField.toString());
                currentField = new StringBuilder();
                rows.add(new ArrayList<>(currentRow));
                currentRow.clear();
            } else if (c == '\r') {
                // ignoruj \r
            } else {
                currentField.append(c);
            }
        }

        // ostatni wiersz
        if (currentField.length() > 0 || !currentRow.isEmpty()) {
            currentRow.add(currentField.toString());
            rows.add(currentRow);
        }

        return rows;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Ekstrakcja ASCII z hex dump
    // ─────────────────────────────────────────────────────────────────────────

    private static String extractAsciiFromDump(String payload) {
        if (payload == null || payload.isBlank()) return "";

        StringBuilder sb = new StringBuilder();
        Matcher m = ASCII_PATTERN.matcher(payload);
        while (m.find()) {
            String ascii = m.group(1).trim();
            // usuń śmieci (znaki kontrolne)
            ascii = ascii.replaceAll("[\\x00-\\x1F\\x7F]", "");
            sb.append(ascii);
        }

        // Fallback: jeśli regex nie złapał nic, wyciągnij prawą kolumnę inaczej
        if (sb.length() == 0) {
            String[] lines = payload.split("\n");
            for (String line : lines) {
                // Każda linia hex dump ma format: "   HEX   ASCII"
                // ASCII zaczyna się po podwójnej spacji za ostatnim bajtem
                int lastHexEnd = line.lastIndexOf("   ");
                if (lastHexEnd > 20 && lastHexEnd + 3 < line.length()) {
                    String ascii = line.substring(lastHexEnd + 3).trim();
                    if (ascii.length() > 2) sb.append(ascii);
                }
            }
        }

        return sb.toString();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Ekstrakcja URL i IP
    // ─────────────────────────────────────────────────────────────────────────

    private static List<String> extractUrls(String text) {
        List<String> urls = new ArrayList<>();
        if (text == null || text.isBlank()) return urls;
        Matcher m = URL_PATTERN.matcher(text);
        while (m.find()) {
            String url = m.group().replaceAll("[,;\"']+$", "");
            if (!urls.contains(url)) urls.add(url);
        }
        return urls;
    }

    private static List<String> extractIps(String text) {
        List<String> ips = new ArrayList<>();
        if (text == null || text.isBlank()) return ips;
        Matcher m = IP_PATTERN.matcher(text);
        while (m.find()) {
            String ip = m.group(1);
            // Pomiń zakresy prywatne i loopback
            if (!ip.startsWith("192.168.") && !ip.startsWith("10.")
                    && !ip.startsWith("172.16.") && !ip.equals("127.0.0.1")) {
                if (!ips.contains(ip)) ips.add(ip);
            }
        }
        return ips;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Klasyfikacja ataków
    // ─────────────────────────────────────────────────────────────────────────

    private static String classifyAttack(String raw, String decoded, String extracted) {
        String all = (raw + " " + decoded + " " + extracted).toLowerCase();

        if (all.contains("wget") || all.contains("curl") || all.contains("busybox")
                || all.contains("chmod") || all.contains("/tmp")) {
            return "MIRAI_BOTNET";
        }
        if (all.contains("nmap") || all.contains("trinity.txt") || all.contains("nice ports")) {
            return "NMAP_SCAN";
        }
        if (all.contains("/etc/passwd") || all.contains("../") || all.contains("%2e%2e")) {
            return "PATH_TRAVERSAL";
        }
        if (all.contains("/mgmt/tm/util/bash") || all.contains("f5") || all.contains("bigip")) {
            return "F5_EXPLOIT";
        }
        if (all.contains(".git/config") || all.contains("/.env") || all.contains("/.aws")) {
            return "CONFIG_EXPOSURE";
        }
        if (all.contains(":443/") || all.contains("https://")) {
            return "HTTPS_PROBE";
        }
        if (!raw.isBlank()) {
            return "UNKNOWN_PAYLOAD";
        }
        return "IP_SCAN";
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Detekcja rodziny malware
    // ─────────────────────────────────────────────────────────────────────────

    private static String detectMalwareFamily(String decoded, String raw) {
        String all = (decoded + " " + raw).toLowerCase();

        if (all.contains("mirai") || all.contains("killall -9") || all.contains("boatnet")) return "Mirai";
        if (all.contains("mozi"))    return "Mozi";
        if (all.contains("gafgyt") || all.contains("bashlite")) return "Gafgyt";
        if (all.contains("realtek") || all.contains("realtec")) return "Mirai/RealTek";
        if (all.contains("ohshit")) return "Mirai/OhShit";
        if (all.contains("sendit.sh")) return "Mirai/SendIt";
        if (all.contains("rondo.kqa")) return "Mirai/Rondo";
        if (all.contains("naga"))    return "Mirai/Naga";
        if (all.contains("axis.mpsl") || all.contains("morte.mpsl") || all.contains("murrez")) return "Mirai/Variant";
        return "Unknown";
    }

    private static boolean isValidIpOrHost(String s) {
        if (s == null || s.isBlank()) return false;
        return s.matches("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$")
            || s.matches("^[a-zA-Z0-9][a-zA-Z0-9._-]+$");
    }
}
