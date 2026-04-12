package org.example;

import org.apache.spark.sql.*;
import org.apache.spark.sql.types.*;

import static org.apache.spark.sql.functions.*;

/**
 * Pipeline ETL: CSV → transformacja → tabela Apache Iceberg (filesystem catalog).
 *
 * Kroki:
 *  1. EXTRACT   – wczytaj pliki CSV
 *  2. TRANSFORM – oczyść i wzbogać dane
 *  3. LOAD      – zapisz do tabel Iceberg (partycje: rok + kategoria)
 */
public class EtlPipeline {

    private final SparkSession spark;
    private final String inputPath;

    private static final String CATALOG  = "local_catalog";
    private static final String DATABASE = "sales_db";

    public EtlPipeline(SparkSession spark, String inputPath) {
        this.spark     = spark;
        this.inputPath = inputPath;
    }

    /** Uruchamia pełny pipeline ETL */
    public void run() {
        System.out.println("=== [ETL] START ===");

        Dataset<Row> raw      = extract();
        Dataset<Row> cleaned  = transform(raw);
        Dataset<Row> enriched = enrich(cleaned);

        loadOrders(enriched);
        loadSummary(enriched);

        showSummary();
        System.out.println("=== [ETL] KONIEC ===");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 1. EXTRACT
    // ─────────────────────────────────────────────────────────────────────────

    private Dataset<Row> extract() {
        System.out.println("[EXTRACT] Wczytuję CSV z: " + inputPath);

        StructType schema = new StructType()
            .add("order_id",     DataTypes.StringType,  false)
            .add("customer_id",  DataTypes.StringType,  false)
            .add("product_id",   DataTypes.StringType,  false)
            .add("product_name", DataTypes.StringType,  true)
            .add("category",     DataTypes.StringType,  true)
            .add("quantity",     DataTypes.IntegerType, true)
            .add("unit_price",   DataTypes.DoubleType,  true)
            .add("order_date",   DataTypes.StringType,  true)
            .add("country",      DataTypes.StringType,  true)
            .add("status",       DataTypes.StringType,  true);

        Dataset<Row> df = spark.read()
            .option("header",    "true")
            .option("multiLine", "true")
            .schema(schema)
            .csv(inputPath);

        System.out.println("[EXTRACT] Wczytano wierszy: " + df.count());
        return df;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. TRANSFORM
    // ─────────────────────────────────────────────────────────────────────────

    private Dataset<Row> transform(Dataset<Row> raw) {
        System.out.println("[TRANSFORM] Czyszczenie danych...");

        Dataset<Row> cleaned = raw
            .filter(col("order_id").isNotNull())
            .filter(col("unit_price").isNotNull().and(col("unit_price").gt(0)))
            .filter(col("quantity").isNotNull().and(col("quantity").gt(0)))
            .withColumn("country",
                when(col("country").isNull().or(col("country").equalTo("")), lit("Unknown"))
                .otherwise(col("country")))
            .withColumn("status",     upper(trim(col("status"))))
            .withColumn("order_date", to_date(col("order_date"), "yyyy-MM-dd"))
            .dropDuplicates("order_id");

        System.out.println("[TRANSFORM] Po czyszczeniu wierszy: " + cleaned.count());
        return cleaned;
    }

    private Dataset<Row> enrich(Dataset<Row> cleaned) {
        System.out.println("[TRANSFORM] Wzbogacanie danych...");

        return cleaned
            .withColumn("order_value",
                round(col("quantity").multiply(col("unit_price")), 2))
            .withColumn("order_year",  year(col("order_date")))
            .withColumn("order_month", month(col("order_date")))
            .withColumn("value_segment",
                when(col("order_value").lt(100),  lit("LOW"))
                .when(col("order_value").lt(500),  lit("MEDIUM"))
                .when(col("order_value").lt(1500), lit("HIGH"))
                .otherwise(lit("PREMIUM")))
            .withColumn("is_successful",
                col("status").isin("COMPLETED", "SHIPPED").cast(DataTypes.BooleanType))
            .withColumn("etl_timestamp", current_timestamp());
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. LOAD
    // ─────────────────────────────────────────────────────────────────────────

    private void loadOrders(Dataset<Row> df) {
        String table = CATALOG + "." + DATABASE + ".orders";
        System.out.println("[LOAD] Zapisuję do tabeli: " + table);

        spark.sql("CREATE DATABASE IF NOT EXISTS " + CATALOG + "." + DATABASE);

        df.writeTo(table)
            .partitionedBy(col("order_year"), col("category"))
            .tableProperty("write.format.default", "parquet")
            .tableProperty("write.parquet.compression-codec", "snappy")
            .createOrReplace();

        System.out.println("[LOAD] Tabela orders gotowa.");
    }

    private void loadSummary(Dataset<Row> df) {
        String table = CATALOG + "." + DATABASE + ".sales_summary";
        System.out.println("[LOAD] Tworzę agregat: " + table);

        Dataset<Row> summary = df
            .filter(col("is_successful").equalTo(true))
            .groupBy("order_year", "order_month", "category", "country")
            .agg(
                count("order_id").alias("total_orders"),
                sum("order_value").alias("total_revenue"),
                avg("order_value").alias("avg_order_value"),
                sum("quantity").alias("total_units_sold"),
                countDistinct("customer_id").alias("unique_customers")
            )
            .withColumn("total_revenue",   round(col("total_revenue"), 2))
            .withColumn("avg_order_value", round(col("avg_order_value"), 2))
            .withColumn("etl_timestamp",   current_timestamp());

        summary.writeTo(table)
            .partitionedBy(col("order_year"), col("category"))
            .createOrReplace();

        System.out.println("[LOAD] Tabela sales_summary gotowa.");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Podsumowanie
    // ─────────────────────────────────────────────────────────────────────────

    private void showSummary() {
        System.out.println("\n========== WYNIKI ETL ==========");

        System.out.println("\n--- TOP 5 kategorii wg przychodu ---");
        spark.sql(
            "SELECT category, SUM(total_revenue) AS revenue, SUM(total_orders) AS orders " +
            "FROM local_catalog.sales_db.sales_summary " +
            "GROUP BY category " +
            "ORDER BY revenue DESC " +
            "LIMIT 5"
        ).show();

        System.out.println("\n--- Przychód miesięczny 2024 ---");
        spark.sql(
            "SELECT order_month, " +
            "       SUM(total_revenue) AS monthly_revenue, " +
            "       SUM(total_orders)  AS monthly_orders " +
            "FROM local_catalog.sales_db.sales_summary " +
            "WHERE order_year = 2024 " +
            "GROUP BY order_month " +
            "ORDER BY order_month"
        ).show();

        System.out.println("\n--- Snapshoty tabeli Iceberg (time travel) ---");
        spark.sql(
            "SELECT committed_at, snapshot_id, operation " +
            "FROM local_catalog.sales_db.orders.snapshots"
        ).show(false);

        System.out.println("=================================\n");
    }
}
