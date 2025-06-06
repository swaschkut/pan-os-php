<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>{$title}</title>
    <!-- Bootstrap CSS (optional for layout/styling) -->
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
    
    <!-- Chart.js CDN -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>

    <style>
        .zero { color: red; }
    </style>
</head>
<body class="container mt-5">
    <h2 class="mb-4">{$title}</h2>

    <div class="row">
        <div class="col-md-6">
            <table class="table table-bordered">
                <thead class="table-light">
                    <tr>
                        <th>Feature</th>
                        <th>Value</th>
                    </tr>
                </thead>
                <tbody>
                    {foreach from=$tabledata key=feature item=value}
                    <tr>
                        <td>{$feature}</td>
                        <td{if $value == 0} class="zero"{/if}>{$value}</td>
                    </tr>
                    {/foreach}
                </tbody>
            </table>
        </div>
        <div class="col-md-6">
            <canvas id="chart" width="400" height="400"></canvas>
        </div>
    </div>

    <script>
        const ctx = document.getElementById('chart').getContext('2d');
        const chart = new Chart(ctx, {
            type: 'pie',
            data: {
                labels: [{foreach from=$tabledata key=feature item=value}"{$feature}"{if !$smarty.foreach.loop.last},{/if}{/foreach}],
                datasets: [{
                    label: '{$title}',
                    data: [{foreach from=$tabledata item=value}{$value}{if !$smarty.foreach.loop.last},{/if}{/foreach}],
                    backgroundColor: [
                        '#007bff', '#28a745', '#dc3545', '#ffc107', '#17a2b8',
                        '#6610f2', '#fd7e14', '#6f42c1', '#20c997', '#e83e8c'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                plugins: {
                    legend: { position: 'bottom' }
                }
            }
        });
    </script>
</body>
</html>
