<?php

// --- Configuration ---
global $argv;

$inputFile = null;
$outputFile = 'output.json'; // Default value

// 1. Parse arguments in the format key=value (e.g., in=input.txt out=output.json)
foreach ($argv as $arg) {
    if (strpos($arg, '=') !== false) {
        list($key, $value) = explode('=', $arg, 2);
        if ($key === 'in') {
            $inputFile = $value;
        } elseif ($key === 'out') {
            $outputFile = $value;
        }
    }
}

// 2. Validation
if (!$inputFile) {
    die("Error: Please provide an input filename.\nUsage: php process_commands2.php in=input.txt [out=output.json]\n");
}

if (!file_exists($inputFile)) {
    die("Error: Input file '{$inputFile}' not found.\n");
}

$commands = [];

// --- Processing Logic ---

$inputLines = file($inputFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
echo "Processing " . count($inputLines) . " commands from '{$inputFile}'...\n";

foreach ($inputLines as $lineNumber => $line) {
    $currentLine = $lineNumber + 1;
    $line = trim($line);

    if (!preg_match('/^pan-os-php\s+/', $line)) {
        continue; // Skipping non-matching lines silently or add echo if preferred
    }

    $commandArgsString = trim(preg_replace('/^pan-os-php\s+/', '', $line));
    $regex = '/(\w+)=([^\s\']+)|\'(\w+)=([^\']+)\'/i';

    if (preg_match_all($regex, $commandArgsString, $matches, PREG_SET_ORDER) === 0) {
        continue;
    }

    $commandObject = [];
    foreach ($matches as $match) {
        if (!empty($match[1])) {
            $key = $match[1];
            $value = $match[2];
        } elseif (!empty($match[3])) {
            $key = $match[3];
            $value = $match[4];
        } else {
            continue;
        }

        if ($key === 'type') {
            $commandObject[$key] = $value;
        } else {
            $commandObject[$key] = $key . '=' . $value;
        }
    }

    if (!empty($commandObject)) {
        $commands[] = $commandObject;
    }
}

// --- Final Output ---

$finalJsonStructure = ['command' => $commands];
$jsonOutput = json_encode($finalJsonStructure, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

if (file_put_contents($outputFile, $jsonOutput) !== false) {
    echo "Success: Output written to '{$outputFile}'.\n";
    echo "Total commands processed: " . count($commands) . "\n";
} else {
    die("Error: Could not write to output file '{$outputFile}'.\n");
}