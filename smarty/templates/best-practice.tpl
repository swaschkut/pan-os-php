<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Best Practice Report</title>
    <style>
        body { font-family: Arial, sans-serif; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f9f9f9; }
        .zero { color: red; }
    </style>
</head>
<body>
    <h2>Best Practice Report</h2>
    <table>
        <thead>
            <tr>
                <th>Feature</th>
                <th>Value</th>
            </tr>
        </thead>
        <tbody>
            {foreach from=$bestpractice key=feature item=value}
            <tr>
                <td>{$feature}</td>
                <td{if $value == 0} class="zero"{/if}>{$value}</td>
            </tr>
            {/foreach}
        </tbody>
    </table>
</body>
</html>