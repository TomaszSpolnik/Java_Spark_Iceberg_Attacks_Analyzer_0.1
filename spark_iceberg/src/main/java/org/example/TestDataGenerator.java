package org.example;

import java.io.*;
import java.nio.file.*;
import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.util.Random;

/**
 * Generuje testowe pliki CSV z danymi sprzedażowymi.
 *
 * Schemat:
 *   order_id, customer_id, product_id, product_name,
 *   category, quantity, unit_price, order_date, country, status
 */
public class TestDataGenerator {

    private static final String[] PRODUCTS = {
        "Laptop Pro 15", "Wireless Mouse", "USB-C Hub", "Monitor 27\"",
        "Mechanical Keyboard", "Webcam HD", "Headphones BT", "SSD 1TB",
        "RAM 32GB", "Desk Lamp LED"
    };

    private static final String[] CATEGORIES = {
        "Computers", "Accessories", "Accessories", "Monitors",
        "Accessories", "Peripherals", "Audio", "Storage",
        "Memory", "Office"
    };

    private static final double[] BASE_PRICES = {
        1299.99, 49.99, 79.99, 599.99,
        149.99,  99.99, 199.99, 249.99,
        189.99,  39.99
    };

    private static final String[] COUNTRIES = {
        "Poland", "Germany", "France", "Czech Republic",
        "Austria", "Netherlands", "Belgium", "Sweden"
    };

    private static final String[] STATUSES = {
        "COMPLETED", "COMPLETED", "COMPLETED", "SHIPPED",
        "PENDING", "CANCELLED", "RETURNED"
    };

    public static void generate(String outputDir, int numberOfFiles, int rowsPerFile) throws IOException {
        Path dir = Paths.get(outputDir);
        Files.createDirectories(dir);

        Random rnd = new Random(42);
        DateTimeFormatter fmt = DateTimeFormatter.ofPattern("yyyy-MM-dd");
        LocalDate startDate = LocalDate.of(2023, 1, 1);

        System.out.println("[Generator] Tworzę " + numberOfFiles + " plik(i) CSV po " + rowsPerFile + " wierszy...");

        for (int f = 0; f < numberOfFiles; f++) {
            Path filePath = dir.resolve(String.format("sales_%03d.csv", f + 1));

            try (BufferedWriter writer = Files.newBufferedWriter(filePath)) {
                writer.write("order_id,customer_id,product_id,product_name," +
                             "category,quantity,unit_price,order_date,country,status");
                writer.newLine();

                for (int r = 0; r < rowsPerFile; r++) {
                    int productIdx = rnd.nextInt(PRODUCTS.length);
                    int daysOffset = rnd.nextInt(365 * 2);
                    double price   = BASE_PRICES[productIdx] * (0.85 + rnd.nextDouble() * 0.30);
                    int quantity   = 1 + rnd.nextInt(10);
                    String status  = STATUSES[rnd.nextInt(STATUSES.length)];
                    // ~3% wierszy z brakującym krajem – do testowania czyszczenia
                    String country = rnd.nextInt(100) < 3 ? "" : COUNTRIES[rnd.nextInt(COUNTRIES.length)];

                    writer.write(String.format(
                        "ORD-%07d,CUST-%05d,PROD-%03d,\"%s\",%s,%d,%.2f,%s,%s,%s",
                        f * rowsPerFile + r + 1,
                        rnd.nextInt(9999) + 1,
                        productIdx + 1,
                        PRODUCTS[productIdx],
                        CATEGORIES[productIdx],
                        quantity,
                        price,
                        startDate.plusDays(daysOffset).format(fmt),
                        country,
                        status
                    ));
                    writer.newLine();
                }
            }
            System.out.println("[Generator] Zapisano: " + filePath);
        }
        System.out.println("[Generator] Gotowe! Łącznie: " + (numberOfFiles * rowsPerFile) + " rekordów.");
    }
}
