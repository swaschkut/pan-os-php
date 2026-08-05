<?php
// Standardwerte setzen (z. B. 1. des Monats 00:00 bis heute 23:59)
$startDateTime = $_POST['start_datetime'] ?? date('Y-m-01\T00:00');
$endDateTime   = $_POST['end_datetime']   ?? date('Y-m-d\T23:59');

$apiData = null;
$apiUrl  = null;
$error   = null;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 1. Automatische Erkennung des Timezone-Offsets (z. B. +02:00 oder +01:00)
    $tz = new DateTimeZone(date_default_timezone_get());
    $offset = (new DateTime('now', $tz))->format('P');

    // 2. Erstellen der ISO 8601 Strings für die API
    $startIso = $startDateTime . $offset;
    $endIso   = $endDateTime . $offset;

    // 3. API-URL zusammenbauen
    $baseUrl = "https://api.energy-charts.info/price";
    $queryParams = [
        'bzn'   => 'DE-LU',
        'start' => $startIso,
        'end'   => $endIso
    ];

    $apiUrl = $baseUrl . '?' . http_build_query($queryParams);

    // 4. API-Abfrage durchführen
    $options = [
        "http" => [
            "method" => "GET",
            "header" => "User-Agent: PHP-Script\r\n"
        ]
    ];
    $context = stream_context_create($options);
    $response = @file_get_contents($apiUrl, false, $context);

    if ($response !== false) {
        $apiData = json_decode($response, true);
    } else {
        $error = "Fehler beim Abrufen der Daten von der API. Bitte prüfen Sie den Zeitraum.";
    }
}
?>
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Energy Charts - Strompreis Abfrage</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 900px; margin: 30px auto; padding: 0 20px; line-height: 1.6; }
        .form-card { background: #f4f7f6; padding: 20px; border-radius: 8px; margin-bottom: 30px; }
        .form-group { display: inline-block; margin-right: 15px; margin-bottom: 10px; }
        label { display: block; font-weight: bold; margin-bottom: 5px; }
        input[type="datetime-local"], button { padding: 8px 12px; font-size: 14px; border-radius: 4px; border: 1px solid #ccc; }
        button { background-color: #0066cc; color: white; border: none; cursor: pointer; }
        button:hover { background-color: #004b99; }
        .error { color: #d9534f; background: #fdf7f7; padding: 10px; border-radius: 4px; border: 1px solid #d9534f; }
        .url-box { background: #f0f0f0; border-left: 4px solid #0066cc; padding: 10px 15px; word-break: break-all; margin-bottom: 20px; font-family: monospace; }
        .summary { background: #eef7ff; padding: 15px; border-radius: 6px; margin-bottom: 20px; }
        table { width: 100%; border-collapse: collapse; margin-top: 15px; }
        th, td { border: 1px solid #ddd; padding: 8px 12px; text-align: left; }
        th { background-color: #f2f2f2; }
        tr:nth-child(even) { background-color: #f9f9f9; }
    </style>
</head>
<body>

<h2>Strompreis-Abfrage (DE-LU)</h2>

<div class="form-card">
    <form method="POST">
        <div class="form-group">
            <label for="start_datetime">Start (Datum & Uhrzeit):</label>
            <input type="datetime-local" id="start_datetime" name="start_datetime" value="<?= htmlspecialchars($startDateTime) ?>" step="3600" required>
        </div>

        <div class="form-group">
            <label for="end_datetime">Ende (Datum & Uhrzeit):</label>
            <input type="datetime-local" id="end_datetime" name="end_datetime" value="<?= htmlspecialchars($endDateTime) ?>" step="3600" required>
        </div>

        <div class="form-group" style="vertical-align: bottom;">
            <button type="submit">Preise abfragen</button>
        </div>
    </form>
</div>

<?php if ($apiUrl): ?>
    <!-- Ausgabe der verwendeten Abfrage-URL -->
    <div class="url-box">
        <strong>Generierte API-URL:</strong><br>
        <a href="<?= htmlspecialchars($apiUrl) ?>" target="_blank" rel="noopener noreferrer">
            <?= htmlspecialchars($apiUrl) ?>
        </a>
    </div>
<?php endif; ?>

<?php if ($error): ?>
    <div class="error"><?= htmlspecialchars($error) ?></div>
<?php endif; ?>

<?php if ($apiData && isset($apiData['unix_seconds'], $apiData['price'])): ?>
    <?php
    $timestamps = $apiData['unix_seconds'];
    $prices = $apiData['price'];
    $unit = $apiData['unit'] ?? 'EUR/MWh';

    // Statistiken berechnen
    $validPrices = array_filter($prices, fn($p) => $p !== null);
    $avgPrice = count($validPrices) > 0 ? array_sum($validPrices) / count($validPrices) : 0;
    $minPrice = count($validPrices) > 0 ? min($validPrices) : 0;
    $maxPrice = count($validPrices) > 0 ? max($validPrices) : 0;
    ?>

    <div class="summary">
        <h3>Zusammenfassung</h3>
        <p>
            <strong>Anzahl Datenpunkte:</strong> <?= count($prices) ?><br>
            <strong>Durchschnittspreis:</strong> <?= number_format($avgPrice, 2, ',', '.') ?> <?= htmlspecialchars($unit) ?><br>
            <strong>Minimalpreis:</strong> <?= number_format($minPrice, 2, ',', '.') ?> <?= htmlspecialchars($unit) ?><br>
            <strong>Maximalpreis:</strong> <?= number_format($maxPrice, 2, ',', '.') ?> <?= htmlspecialchars($unit) ?>
        </p>
    </div>

    <h3>Preisverlauf</h3>
    <table>
        <thead>
        <tr>
            <th>Datum & Uhrzeit</th>
            <th>Preis (<?= htmlspecialchars($unit) ?>)</th>
            <th>Preis (ct/kWh)</th>
        </tr>
        </thead>
        <tbody>
        <?php foreach ($timestamps as $index => $timestamp): ?>
            <?php
            $priceMwh = $prices[$index] ?? null;
            $priceCtKwh = $priceMwh !== null ? $priceMwh / 10 : null;
            ?>
            <tr>
                <td><?= date('d.m.Y H:i', $timestamp) ?> Uhr</td>
                <td><?= $priceMwh !== null ? number_format($priceMwh, 2, ',', '.') : '-' ?></td>
                <td><?= $priceCtKwh !== null ? number_format($priceCtKwh, 2, ',', '.') . ' ct' : '-' ?></td>
            </tr>
        <?php endforeach; ?>
        </tbody>
    </table>
<?php endif; ?>

</body>
</html>