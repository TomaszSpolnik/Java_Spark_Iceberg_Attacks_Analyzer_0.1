package org.example;

import org.apache.spark.sql.SparkSession;
import org.example.pipeline.ThreatPipeline;

import java.nio.file.Paths;

/**
 * Punkt wejscia — analiza zagrozen z pliku CSV.
 *
 * Uzycie domyslne (plik w data/input/attacks.csv):
 *   java -jar target/spark_iceberg-1.0-SNAPSHOT.jar
 *
 * Uzycie z wlasna sciezka:
 *   java -jar target/spark_iceberg-1.0-SNAPSHOT.jar /sciezka/do/pliku.csv
 */
public class Main {

    public static void main(String[] args) throws Exception {

        String csvPath;
        if (args.length > 0) {
            csvPath = args[0];
        } else {
            String projectRoot = System.getProperty("user.dir");
            csvPath = Paths.get(projectRoot, "data", "input", "attacks.csv").toString();
        }

        String warehousePath = Paths.get(
            System.getProperty("user.dir"), "data", "warehouse"
        ).toString();

        System.out.println("[MAIN] Plik wejsciowy: " + csvPath);
        System.out.println("[MAIN] Warehouse:      " + warehousePath);

        SparkSession spark = SparkSession.builder()
            .appName("Threat Analysis ETL")
            .master("local[*]")
            .config("spark.sql.extensions",
                "org.apache.iceberg.spark.extensions.IcebergSparkSessionExtensions")
            .config("spark.sql.catalog.local_catalog",
                "org.apache.iceberg.spark.SparkCatalog")
            .config("spark.sql.catalog.local_catalog.type",      "hadoop")
            .config("spark.sql.catalog.local_catalog.warehouse", warehousePath)
            .config("spark.ui.showConsoleProgress", "false")
            .config("spark.sql.adaptive.enabled",   "true")
            .getOrCreate();

        spark.sparkContext().setLogLevel("WARN");
        System.out.println("[MAIN] Spark " + spark.version() + " uruchomiony.");

        new ThreatPipeline(spark, csvPath).run();

        spark.stop();
        System.out.println("[MAIN] Koniec.");
    }
}
