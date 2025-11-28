<?php

// --- Configuration ---
// Read input file name from command line arguments ($argv[1])
global $argv; // Ensure $argv is available, though it often is globally.

if (!isset($argv[1])) {
    // If the argument is missing, display an error and exit.
    die("Error: Please provide the input filename as a command-line argument.\nUsage: php process_commands.php <input_filename>\n");
}

$inputFile = $argv[1];
$outputFile = 'output.json';
$commands = [];

// Check if the input file exists
if (!file_exists($inputFile)) {
    die("Error: Input file '{$inputFile}' not found.\n");
}

// Read the input file into an array of lines, skipping empty lines
$inputLines = file($inputFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);

echo "Processing " . count($inputLines) . " commands from '{$inputFile}'...\n";

foreach ($inputLines as $lineNumber => $line) {
    $currentLine = $lineNumber + 1;

    // 1. Normalize and clean the line: remove leading/trailing whitespace.
    $line = trim($line);

    // 2. Skip lines that don't start with the expected command prefix
    if (!preg_match('/^pan-os-php\s+/', $line)) {
        echo "Warning: Skipping line {$currentLine} (does not start with 'pan-os-php').\n";
        continue;
    }

    // 3. Remove the command name "pan-os-php" and any subsequent whitespace
    $commandArgsString = trim(preg_replace('/^pan-os-php\s+/', '', $line));

    // 4. Use a robust regular expression to parse key=value arguments:
    // This combined pattern handles two types of arguments:
    //   A) Unquoted key=value (e.g., type=upload) -> Groups 1 & 2
    //   B) Single-quoted 'key=value...' (e.g., 'filter=(to has Eth3)') -> Groups 3 & 4
    $regex = '/(\w+)=([^\s\']+)|\'(\w+)=([^\']+)\'/i';

    if (preg_match_all($regex, $commandArgsString, $matches, PREG_SET_ORDER) === 0) {
        echo "Warning: Could not parse arguments on line {$currentLine}.\n";
        continue;
    }

    $commandObject = [];
    foreach ($matches as $match) {
        $key = '';
        $value = '';

        if (!empty($match[1])) {
            // Matched unquoted format: key=value
            $key = $match[1];
            $value = $match[2];
        } elseif (!empty($match[3])) {
            // Matched single-quoted format: 'key=value'
            $key = $match[3];
            $value = $match[4];
        } else {
            // Should not happen, but safe to skip
            continue;
        }

        // Based on the user's desired output format:
        if ($key === 'type') {
            // 'type' is stored only as the value (e.g., "upload")
            $commandObject[$key] = $value;
        } else {
            // All other keys are stored as "key": "key=value"
            $commandObject[$key] = $key . '=' . $value;
        }
    }

    if (!empty($commandObject)) {
        $commands[] = $commandObject;
    }
}

// Structure the final JSON output
$finalJsonStructure = [
    'command' => $commands
];

// Encode the structure into a JSON string
// JSON_PRETTY_PRINT for readable output
// JSON_UNESCAPED_SLASHES to keep XPaths and filters clean (e.g., avoiding escaping of '/')
$jsonOutput = json_encode($finalJsonStructure, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

// Write the JSON string to the output file
if (file_put_contents($outputFile, $jsonOutput) !== false) {
    echo "Success: Output written to '{$outputFile}'.\n";
    echo "Total commands processed: " . count($commands) . "\n";
} else {
    die("Error: Could not write to output file '{$outputFile}'.\n");
}

?>