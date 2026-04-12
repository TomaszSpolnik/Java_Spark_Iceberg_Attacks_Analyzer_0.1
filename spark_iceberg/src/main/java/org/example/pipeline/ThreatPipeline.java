package org.example.pipeline;

import org.apache.spark.sql.*;
import org.apache.spark.sql.types.*;
import org.example.model.AttackRecord;
import org.example.parser.CsvParser;

import java.util.*;
import java.util.stream.Collectors;

import static org.apache.spark.sql.functions.*;

/**
 * Pipeline analizy zagrozen:
 *   1. Parsuj plik CSV (wieloliniowy, nieregularny format)
 *   2. Zaladuj dane do Sparka
 *   3. Zapisz do 3 tabel Iceberg:
 *      - threat_events   (wszystkie zdarzenia)
 *      - blacklist_ips   (IP do zablokowania)
 *      - blacklist_urls  (URL/domeny do zablokowania)
 *   4. Wyswietl raport
 */
public class ThreatPipeline {

    private final SparkSession spark;
    private final String csvPath;

    private static final String CATALOG  = "local_catalog";
    private static final String DATABASE = "threat_db";

    public ThreatPipeline(SparkSession spark, String csvPath) {
        this.spark   = spark;
        this.csvPath = csvPath;
    }

    public void run() throws Exception {
        System.out.println("=== [THREAT ETL] START ===");

        System.out.println("[PARSE] Wczytuję plik: " + csvPath);
        List<AttackRecord> records = CsvParser.parse(csvPath);
        System.out.println("[PARSE] Sparsowano rekordow: " + records.size());

        Dataset<Row> events    = toEventsDataFrame(records);
        Dataset<Row> blackIps  = toBlacklistIpDataFrame(records);
        Dataset<Row> blackUrls = toBlacklistUrlDataFrame(records);

        spark.sql("CREATE DATABASE IF NOT EXISTS " + CATALOG + "." + DATABASE);

        saveTable(events,    "threat_events",  "attack_type");
        saveTable(blackIps,  "blacklist_ips",  "threat_level");
        saveTable(blackUrls, "blacklist_urls", "threat_level");

        showReport();

        System.out.println("=== [THREAT ETL] KONIEC ===");
    }

    // -------------------------------------------------------------------------
    // DataFrames
    // -------------------------------------------------------------------------

    private Dataset<Row> toEventsDataFrame(List<AttackRecord> records) {
        StructType schema = new StructType()
            .add("source_ip",       DataTypes.StringType)
            .add("attack_type",     DataTypes.StringType)
            .add("malware_family",  DataTypes.StringType)
            .add("decoded_payload", DataTypes.StringType)
            .add("extracted_urls",  DataTypes.StringType)
            .add("extracted_ips",   DataTypes.StringType)
            .add("raw_extracted",   DataTypes.StringType)
            .add("has_payload",     DataTypes.BooleanType)
            .add("url_count",       DataTypes.IntegerType)
            .add("ip_count",        DataTypes.IntegerType);

        List<Row> rows = records.stream().map(r -> RowFactory.create(
            r.sourceIp,
            r.attackType,
            r.malwareFamily,
            r.decodedPayload.length() > 500 ? r.decodedPayload.substring(0, 500) : r.decodedPayload,
            String.join("|", r.extractedUrls),
            String.join("|", r.extractedIps),
            r.rawExtracted,
            !r.decodedPayload.isBlank(),
            r.extractedUrls.size(),
            r.extractedIps.size()
        )).collect(Collectors.toList());

        return spark.createDataFrame(rows, schema)
            .withColumn("etl_timestamp", current_timestamp());
    }

    private Dataset<Row> toBlacklistIpDataFrame(List<AttackRecord> records) {
        Map<String, String> ipToType = new LinkedHashMap<>();

        for (AttackRecord r : records) {
            ipToType.put(r.sourceIp, r.attackType);
            for (String ip : r.extractedIps) {
                if (!ip.equals(r.sourceIp)) {
                    ipToType.put(ip, "C2_SERVER");
                }
            }
            if (!r.rawExtracted.isBlank()) {
                String extracted = r.rawExtracted.replaceAll("/\\d+$", "").trim();
                if (extracted.matches("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$")) {
                    ipToType.put(extracted, "EXTRACTED_C2");
                }
            }
        }

        StructType schema = new StructType()
            .add("ip_address",   DataTypes.StringType)
            .add("threat_level", DataTypes.StringType)
            .add("source",       DataTypes.StringType);

        List<Row> rows = ipToType.entrySet().stream().map(e -> {
            String level = e.getValue().contains("BOTNET") || e.getValue().contains("C2")
                ? "HIGH" : "MEDIUM";
            return RowFactory.create(e.getKey(), level, e.getValue());
        }).collect(Collectors.toList());

        return spark.createDataFrame(rows, schema)
            .withColumn("etl_timestamp", current_timestamp());
    }

    private Dataset<Row> toBlacklistUrlDataFrame(List<AttackRecord> records) {
        Map<String, String> urlToFamily = new LinkedHashMap<>();
        for (AttackRecord r : records) {
            for (String url : r.extractedUrls) {
                urlToFamily.put(url, r.malwareFamily);
            }
        }

        StructType schema = new StructType()
            .add("url",            DataTypes.StringType)
            .add("malware_family", DataTypes.StringType)
            .add("threat_level",   DataTypes.StringType);

        List<Row> rows = urlToFamily.entrySet().stream().map(e ->
            RowFactory.create(e.getKey(), e.getValue(), "HIGH")
        ).collect(Collectors.toList());

        return spark.createDataFrame(rows, schema)
            .withColumn("etl_timestamp", current_timestamp());
    }

    // -------------------------------------------------------------------------
    // Zapis do Iceberg
    // -------------------------------------------------------------------------

    private void saveTable(Dataset<Row> df, String tableName, String partitionCol) {
        String fullName = CATALOG + "." + DATABASE + "." + tableName;
        System.out.println("[LOAD] Zapisuję: " + fullName + " (" + df.count() + " rekordow)");
        df.writeTo(fullName)
            .partitionedBy(col(partitionCol))
            .tableProperty("write.format.default", "parquet")
            .createOrReplace();
        System.out.println("[LOAD] Gotowe: " + fullName);
    }

    // -------------------------------------------------------------------------
    // Raport
    // -------------------------------------------------------------------------

    private void showReport() {
        System.out.println("\n");
        System.out.println("╔══════════════════════════════════════════════════════╗");
        System.out.println("║           RAPORT ANALIZY ZAGROZEN                   ║");
        System.out.println("╚══════════════════════════════════════════════════════╝");

        System.out.println("\n 1. TYPY ATAKOW");
        spark.sql(
            "SELECT attack_type, COUNT(*) AS count, " +
            "COUNT(CASE WHEN has_payload THEN 1 END) AS with_payload " +
            "FROM local_catalog.threat_db.threat_events " +
            "GROUP BY attack_type ORDER BY count DESC"
        ).show(false);

        System.out.println(" 2. RODZINY MALWARE");
        spark.sql(
            "SELECT malware_family, COUNT(*) AS infected_sources " +
            "FROM local_catalog.threat_db.threat_events " +
            "WHERE malware_family != 'Unknown' " +
            "GROUP BY malware_family ORDER BY infected_sources DESC"
        ).show(false);

        System.out.println(" 3. BLACKLISTA IP (pierwsze 20, posortowane po poziomie zagrozenia)");
        spark.sql(
            "SELECT ip_address, threat_level, source " +
            "FROM local_catalog.threat_db.blacklist_ips " +
            "ORDER BY threat_level DESC, ip_address LIMIT 20"
        ).show(false);

        System.out.println(" 4. BLACKLISTA URL — serwery C2 i download");
        spark.sql(
            "SELECT url, malware_family " +
            "FROM local_catalog.threat_db.blacklist_urls " +
            "ORDER BY malware_family"
        ).show(100, false);

        System.out.println(" 5. PODSUMOWANIE");
        spark.sql(
            "SELECT " +
            "(SELECT COUNT(*) FROM local_catalog.threat_db.blacklist_ips)  AS total_blocked_ips, " +
            "(SELECT COUNT(*) FROM local_catalog.threat_db.blacklist_urls) AS total_blocked_urls, " +
            "(SELECT COUNT(*) FROM local_catalog.threat_db.threat_events)  AS total_events"
        ).show(false);

        System.out.println(" 6. IP Z NAJWIEKSZA LICZBA WYEKSTRAKTOWANYCH ADRESOW C2");
        spark.sql(
            "SELECT source_ip, attack_type, malware_family, ip_count, url_count " +
            "FROM local_catalog.threat_db.threat_events " +
            "WHERE ip_count > 0 OR url_count > 0 " +
            "ORDER BY ip_count DESC, url_count DESC LIMIT 15"
        ).show(false);
    }
}
