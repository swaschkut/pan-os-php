<?php
// Retrieve current script filename dynamically
$currentScript = htmlspecialchars($_SERVER['SCRIPT_NAME']);

// Default search bounds (August 1–3, 2026)
$defaultStart = '2026-08-01T00:00';
$defaultEnd   = '2026-08-03T23:59';

$startDate = isset($_GET['start']) ? $_GET['start'] : $defaultStart;
$endDate   = isset($_GET['end'])   ? $_GET['end']   : $defaultEnd;

// Selected Timezone offset in hours (Default: 0 for UTC+0)
$tzOffset = isset($_GET['tz']) ? (int)$_GET['tz'] : 0;
if (!in_array($tzOffset, [0, 1, 2])) {
    $tzOffset = 0;
}
$tzOffsetSeconds = $tzOffset * 3600;

// Parse Period 1 via DateTime object
try {
    $dt1Start = new DateTime($startDate);
    $dt1End   = new DateTime($endDate);
} catch (Exception $e) {
    $dt1Start = new DateTime($defaultStart);
    $dt1End   = new DateTime($defaultEnd);
}

$startTimestamp1 = $dt1Start->getTimestamp();
$endTimestamp1   = $dt1End->getTimestamp();

// Calculate range duration in seconds to preserve it when shifting
$duration = $endTimestamp1 - $startTimestamp1;

// Handle Shift Button Actions
if (isset($_GET['shift'])) {
    $shiftAction = trim($_GET['shift']);
    $newStartTimestamp = $startTimestamp1;

    switch ($shiftAction) {
        case '-1month':
            $newStartTimestamp = strtotime('-1 month', $startTimestamp1);
            break;
        case '+1month':
        case '1month':
            $newStartTimestamp = strtotime('+1 month', $startTimestamp1);
            break;
        case '-7days':
            $newStartTimestamp = strtotime('-7 days', $startTimestamp1);
            break;
        case '+7days':
        case '7days':
            $newStartTimestamp = strtotime('+7 days', $startTimestamp1);
            break;
    }

    $newEndTimestamp = $newStartTimestamp + $duration;

    // Redirect dynamically to current script preserving timezone and updated dates
    $newStart = date('Y-m-d\TH:i', $newStartTimestamp);
    $newEnd   = date('Y-m-d\TH:i', $newEndTimestamp);
    header("Location: " . $_SERVER['SCRIPT_NAME'] . "?start=" . urlencode($newStart) . "&end=" . urlencode($newEnd) . "&tz=" . $tzOffset);
    exit;
}

// Period 2 (1 year prior)
$dt2Start = (clone $dt1Start)->modify('-1 year');
$dt2End   = (clone $dt1End)->modify('-1 year');
$startTimestamp2 = $dt2Start->getTimestamp();
$endTimestamp2   = $dt2End->getTimestamp();

// Period 3 (2 years prior)
$dt3Start = (clone $dt1Start)->modify('-2 years');
$dt3End   = (clone $dt1End)->modify('-2 years');
$startTimestamp3 = $dt3Start->getTimestamp();
$endTimestamp3   = $dt3End->getTimestamp();

// Years for Labels
$year1 = $dt1Start->format('Y');
$year2 = $dt2Start->format('Y');
$year3 = $dt3Start->format('Y');

// 1. Load and merge ALL JSON files in folder
$jsonFiles = glob(__DIR__ . '/*.json');
$masterData = [];

if ($jsonFiles) {
    foreach ($jsonFiles as $filePath) {
        $rawContent = file_get_contents($filePath);
        $json = json_decode($rawContent, true);

        if (isset($json['unix_seconds']) && is_array($json['unix_seconds'])) {
            $timestamps = $json['unix_seconds'];
            $prices = isset($json['price']) ? $json['price'] : (isset($json['data']) ? $json['data'] : (isset($json['values']) ? $json['values'] : []));

            foreach ($timestamps as $index => $timestamp) {
                if (isset($prices[$index])) {
                    $masterData[$timestamp] = $prices[$index];
                }
            }
        }
    }
}

ksort($masterData);

// 2. Build 15-minute grid aligned across years
$finalLabels  = [];
$finalSeries1 = [];
$finalSeries2 = [];
$finalSeries3 = [];
$finalSeries4 = []; // Period 4: 60-minute resolution calculated from 15m averages

// Helper function: standard 15-minute resolution with hourly fallback
function getPriceForTime15m($masterData, $targetTimestamp) {
    $rounded15m = floor($targetTimestamp / 900) * 900;
    if (isset($masterData[$rounded15m])) {
        return (int)round($masterData[$rounded15m] / 10, 0);
    }

    $hourly = floor($targetTimestamp / 3600) * 3600;
    if (isset($masterData[$hourly])) {
        return (int)round($masterData[$hourly] / 10, 0);
    }

    return null;
}

// Helper function: 60-minute value calculated as average of 4 x 15-minute slots (if present)
function getPriceForTime60m($masterData, $targetTimestamp) {
    $hourly = floor($targetTimestamp / 3600) * 3600;

    // Timestamps for the 4 sub-intervals in this hour
    $t0  = $hourly;
    $t15 = $hourly + 900;
    $t30 = $hourly + 1800;
    $t45 = $hourly + 2700;

    // Check if 15-minute readings exist for all 4 slots
    if (isset($masterData[$t0], $masterData[$t15], $masterData[$t30], $masterData[$t45])) {
        $avgRaw = ($masterData[$t0] + $masterData[$t15] + $masterData[$t30] + $masterData[$t45]) / 4;
        return (int)round($avgRaw / 10, 0);
    }

    // Fallback if 15-minute granularity isn't available for all 4 slots
    if (isset($masterData[$hourly])) {
        return (int)round($masterData[$hourly] / 10, 0);
    }

    return null;
}

// Iterate through selected period in 15-minute steps
for ($curr1 = $startTimestamp1; $curr1 <= $endTimestamp1; $curr1 += 900) {
    // Format X-axis label adjusted to selected timezone offset
    $adjustedTimestamp = $curr1 + $tzOffsetSeconds;
    $label = gmdate('d.m. H:i', $adjustedTimestamp);
    $finalLabels[] = $label;

    // Synchronized timestamps for Period 2 & Period 3
    $offset = $curr1 - $startTimestamp1;
    $curr2 = $startTimestamp2 + $offset;
    $curr3 = $startTimestamp3 + $offset;

    // Fetch rounded data values in Euro cents
    $finalSeries1[] = getPriceForTime15m($masterData, $curr1);
    $finalSeries2[] = getPriceForTime15m($masterData, $curr2);
    $finalSeries3[] = getPriceForTime15m($masterData, $curr3);
    $finalSeries4[] = getPriceForTime60m($masterData, $curr1); // Calculates (v0 + v15 + v30 + v45) / 4
}

// Stats calculation helper
function calculateStats($dataArray) {
    $valid = array_filter($dataArray, function($v) { return !is_null($v); });
    $count = count($valid);
    if ($count === 0) return ['avg' => 0, 'max' => 0, 'min' => 0, 'count' => 0];
    return [
        'avg'   => (int)round(array_sum($valid) / $count, 0),
        'max'   => max($valid),
        'min'   => min($valid),
        'count' => $count
    ];
}

$stats1 = calculateStats($finalSeries1);
$stats2 = calculateStats($finalSeries2);
$stats3 = calculateStats($finalSeries3);
$stats4 = calculateStats($finalSeries4);
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Multi-Period Electricity Price Comparison Overlay</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 30px;
            background-color: #f4f6f9;
            color: #333;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: #fff;
            padding: 25px;
            border-radius: 10px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.08);
        }
        .controls-wrapper {
            background: #f8f9fa;
            padding: 15px;
            border-radius: 6px;
            margin-bottom: 25px;
            display: flex;
            flex-direction: column;
            gap: 15px;
        }
        form {
            display: flex;
            gap: 15px;
            align-items: center;
            flex-wrap: wrap;
        }
        .form-group { display: flex; flex-direction: column; gap: 5px; }
        label { font-weight: 600; font-size: 0.85em; color: #495057; }
        input[type="datetime-local"], select {
            padding: 8px 12px;
            border: 1px solid #ced4da;
            border-radius: 4px;
            background-color: #fff;
        }

        .btn-submit {
            padding: 9px 18px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            font-weight: 600;
            cursor: pointer;
            margin-top: 18px;
        }
        .btn-submit:hover { background-color: #0056b3; }

        .shift-controls {
            display: flex;
            gap: 10px;
            align-items: center;
            border-top: 1px solid #dee2e6;
            padding-top: 12px;
        }
        .shift-label {
            font-weight: 600;
            font-size: 0.85em;
            color: #495057;
            margin-right: 5px;
        }
        .btn-shift {
            padding: 6px 12px;
            background-color: #6c757d;
            color: white;
            text-decoration: none;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
            transition: background 0.2s;
        }
        .btn-shift:hover { background-color: #495057; }

        .comparison-summary { display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin-bottom: 25px; }
        .period-box { padding: 15px; border-radius: 6px; background: #f8f9fa; }
        .period-box.p1 { border-top: 4px solid #007bff; }
        .period-box.p2 { border-top: 4px solid #e83e8c; }
        .period-box.p3 { border-top: 4px solid #28a745; }
        .period-box.p4 { border-top: 4px solid #fd7e14; }
        .period-title { font-weight: bold; margin-bottom: 5px; font-size: 0.95em; }
        .stats-row { display: flex; flex-direction: column; gap: 4px; font-size: 0.85em; margin-top: 8px; }
        .chart-container { position: relative; height: 500px; width: 100%; }
    </style>
</head>
<body>

<div class="container">
    <h2>Multi-Period Electricity Price Comparison Overlay</h2>

    <div class="controls-wrapper">
        <form method="GET" action="<?php echo $currentScript; ?>">
            <div class="form-group">
                <label for="start">Selected Start Date & Time:</label>
                <input type="datetime-local" id="start" name="start" value="<?php echo htmlspecialchars($startDate); ?>">
            </div>
            <div class="form-group">
                <label for="end">Selected End Date & Time:</label>
                <input type="datetime-local" id="end" name="end" value="<?php echo htmlspecialchars($endDate); ?>">
            </div>
            <div class="form-group">
                <label for="tz">Timezone:</label>
                <select id="tz" name="tz">
                    <option value="0" <?php echo $tzOffset === 0 ? 'selected' : ''; ?>>UTC+0 (UTC)</option>
                    <option value="1" <?php echo $tzOffset === 1 ? 'selected' : ''; ?>>UTC+1 (CET)</option>
                    <option value="2" <?php echo $tzOffset === 2 ? 'selected' : ''; ?>>UTC+2 (CEST)</option>
                </select>
            </div>
            <button type="submit" class="btn-submit">Apply Range</button>
        </form>

        <div class="shift-controls">
            <span class="shift-label">Quick Shift Start Date:</span>
            <a href="<?php echo $currentScript; ?>?start=<?php echo urlencode($startDate); ?>&end=<?php echo urlencode($endDate); ?>&tz=<?php echo $tzOffset; ?>&shift=-1month" class="btn-shift">« -1 Month</a>
            <a href="<?php echo $currentScript; ?>?start=<?php echo urlencode($startDate); ?>&end=<?php echo urlencode($endDate); ?>&tz=<?php echo $tzOffset; ?>&shift=-7days" class="btn-shift">‹ -7 Days</a>
            <a href="<?php echo $currentScript; ?>?start=<?php echo urlencode($startDate); ?>&end=<?php echo urlencode($endDate); ?>&tz=<?php echo $tzOffset; ?>&shift=%2B7days" class="btn-shift">+7 Days ›</a>
            <a href="<?php echo $currentScript; ?>?start=<?php echo urlencode($startDate); ?>&end=<?php echo urlencode($endDate); ?>&tz=<?php echo $tzOffset; ?>&shift=%2B1month" class="btn-shift">+1 Month »</a>
        </div>
    </div>

    <div class="comparison-summary">
        <div class="period-box p1">
            <div class="period-title" style="color: #007bff;">Period 1 (<?php echo $dt1Start->format('Y-m-d'); ?>) 15m</div>
            <div class="stats-row">
                <span>Avg: <strong><?php echo number_format($stats1['avg'], 0); ?> ct/kWh</strong></span>
                <span>Max: <strong><?php echo number_format($stats1['max'], 0); ?> ct/kWh</strong></span>
                <span>Min: <strong><?php echo number_format($stats1['min'], 0); ?> ct/kWh</strong></span>
                <span>Points: <strong><?php echo $stats1['count']; ?></strong></span>
            </div>
        </div>

        <div class="period-box p4">
            <div class="period-title" style="color: #fd7e14;">Period 4 (<?php echo $dt1Start->format('Y-m-d'); ?>) 60m Avg</div>
            <div class="stats-row">
                <span>Avg: <strong><?php echo number_format($stats4['avg'], 0); ?> ct/kWh</strong></span>
                <span>Max: <strong><?php echo number_format($stats4['max'], 0); ?> ct/kWh</strong></span>
                <span>Min: <strong><?php echo number_format($stats4['min'], 0); ?> ct/kWh</strong></span>
                <span>Points: <strong><?php echo $stats4['count']; ?></strong></span>
            </div>
        </div>

        <div class="period-box p2">
            <div class="period-title" style="color: #e83e8c;">Period 2 (<?php echo $dt2Start->format('Y-m-d'); ?>)</div>
            <div class="stats-row">
                <span>Avg: <strong><?php echo number_format($stats2['avg'], 0); ?> ct/kWh</strong></span>
                <span>Max: <strong><?php echo number_format($stats2['max'], 0); ?> ct/kWh</strong></span>
                <span>Min: <strong><?php echo number_format($stats2['min'], 0); ?> ct/kWh</strong></span>
                <span>Points: <strong><?php echo $stats2['count']; ?></strong></span>
            </div>
        </div>

        <div class="period-box p3">
            <div class="period-title" style="color: #28a745;">Period 3 (<?php echo $dt3Start->format('Y-m-d'); ?>)</div>
            <div class="stats-row">
                <span>Avg: <strong><?php echo number_format($stats3['avg'], 0); ?> ct/kWh</strong></span>
                <span>Max: <strong><?php echo number_format($stats3['max'], 0); ?> ct/kWh</strong></span>
                <span>Min: <strong><?php echo number_format($stats3['min'], 0); ?> ct/kWh</strong></span>
                <span>Points: <strong><?php echo $stats3['count']; ?></strong></span>
            </div>
        </div>
    </div>

    <div class="chart-container">
        <canvas id="priceChart"></canvas>
    </div>
</div>

<script>
    const labels = <?php echo json_encode($finalLabels); ?>;
    const series1 = <?php echo json_encode($finalSeries1); ?>;
    const series2 = <?php echo json_encode($finalSeries2); ?>;
    const series3 = <?php echo json_encode($finalSeries3); ?>;
    const series4 = <?php echo json_encode($finalSeries4); ?>;
    const selectedTz = "UTC+<?php echo $tzOffset; ?>";

    const ctx = document.getElementById('priceChart').getContext('2d');
    const priceChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [
                {
                    label: 'Selected Period (<?php echo $year1; ?>) - 15m',
                    data: series1,
                    borderColor: '#007bff',
                    backgroundColor: 'rgba(0, 123, 255, 0.05)',
                    borderWidth: 2,
                    fill: false,
                    pointRadius: 0,
                    pointHoverRadius: 5,
                    spanGaps: true,
                    stepped: 'before'
                },
                {
                    label: 'Selected Period (<?php echo $year1; ?>) - 60m Avg',
                    data: series4,
                    borderColor: '#fd7e14',
                    borderDash: [5, 5],
                    borderWidth: 2,
                    fill: false,
                    pointRadius: 0,
                    pointHoverRadius: 5,
                    spanGaps: true,
                    stepped: 'before'
                },
                {
                    label: '1 Year Prior (<?php echo $year2; ?>)',
                    data: series2,
                    borderColor: '#e83e8c',
                    borderWidth: 2,
                    fill: false,
                    pointRadius: 0,
                    pointHoverRadius: 5,
                    spanGaps: true,
                    stepped: 'before'
                },
                {
                    label: '2 Years Prior (<?php echo $year3; ?>)',
                    data: series3,
                    borderColor: '#28a745',
                    borderWidth: 2,
                    fill: false,
                    pointRadius: 0,
                    pointHoverRadius: 5,
                    spanGaps: true,
                    stepped: 'before'
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            scales: {
                x: {
                    title: { display: true, text: 'Date & Time (' + selectedTz + ')' },
                    ticks: {
                        autoSkip: true,
                        maxTicksLimit: 12
                    }
                },
                y: {
                    title: { display: true, text: 'Price (ct/kWh)' },
                    ticks: {
                        precision: 0,
                        callback: function(value) { return Math.round(value) + ' ct'; }
                    }
                }
            },
            plugins: {
                tooltip: {
                    callbacks: {
                        label: function(context) {
                            const val = context.parsed.y;
                            return context.dataset.label + ': ' + (val !== null ? Math.round(val) + ' ct/kWh' : 'No Data');
                        }
                    }
                }
            }
        }
    });
</script>

</body>
</html>