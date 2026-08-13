<?php

class IronSkilletManager {
    private $basePath;
    private $supportedVersions = [];
    private $fileStructure = [];
    private $predefinedXmlPath;

    // Target Profiles filter
    private $targetProfiles = ['Outbound-URL', 'Alert-Only-URL'];

    public function __construct($basePath, $predefinedXmlPath) {
        $this->basePath = rtrim($basePath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        $this->predefinedXmlPath = $predefinedXmlPath;
    }

    public function getPredefinedUrlCategories() {
        $xmlContent = @file_get_contents($this->predefinedXmlPath);
        if ($xmlContent === false) {
            throw new Exception("Could not load predefined.xml from: " . $this->predefinedXmlPath);
        }

        $xml = simplexml_load_string($xmlContent);
        if ($xml === false) {
            throw new Exception("Failed to parse predefined.xml structure.");
        }

        $categories = [];
        if (isset($xml->{'pan-url-categories'})) {
            foreach ($xml->{'pan-url-categories'}->entry as $entry) {
                if (isset($entry['name'])) {
                    $categories[] = (string)$entry['name'];
                }
            }
        }
        if (empty($categories) && isset($xml->{'pan-url-categories'}->member)) {
            foreach ($xml->{'pan-url-categories'}->member as $member) {
                $categories[] = (string)$member;
            }
        }

        return $categories;
    }

    public function scanRepository() {
        if (!is_dir($this->basePath)) {
            throw new Exception("The provided base path does not exist: " . $this->basePath);
        }

        $directories = scandir($this->basePath);
        foreach ($directories as $dir) {
            if ($dir === '.' || $dir === '..') continue;

            $fullPath = $this->basePath . $dir;
            if (is_dir($fullPath) && (preg_match('/^v?\d+\.\d+/', $dir) || strpos($dir, 'panos_v') === 0)) {
                $version = $dir;
                $this->supportedVersions[] = $version;
                $this->fileStructure[$version] = [
                    'url_filtering' => []
                ];
                $this->scanVersionTemplates($fullPath, $version);
            }
        }
        return $this->fileStructure;
    }

    private function scanVersionTemplates($versionPath, $version) {
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($versionPath));
        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'xml') {
                if ($file->getFilename() === 'profiles_url_filtering.xml') {
                    $this->fileStructure[$version]['url_filtering'][] = [
                        'name' => $file->getFilename(),
                        'path' => $file->getRealPath()
                    ];
                }
            }
        }
    }

    /**
     * Inspects target profiles, appends missing predefined categories straight into <alert>,
     * and reorganizes all members within <alert> to be alphabetically sorted.
     */
    public function syncMissingToAlertSection($filePath, array $masterCategories) {
        $content = file_get_contents($filePath);
        if (!$content) return [];

        $hasTemporaryRoot = false;
        if (strpos(trim($content), '<root>') === false) {
            $content = "<root>\n" . $content . "\n</root>";
            $hasTemporaryRoot = true;
        }

        $xml = @simplexml_load_string($content);
        if ($xml === false) {
            throw new Exception("XML template is corrupted or unparsable: " . $filePath);
        }

        $summary = [];

        foreach ($xml->xpath('//entry') as $entry) {
            $profileName = (string)$entry['name'];

            if (!in_array($profileName, $this->targetProfiles)) {
                continue;
            }

            // Gather elements for standard section check
            $directAlertMembers = [];
            if (isset($entry->alert->member)) {
                foreach ($entry->alert->member as $member) {
                    $directAlertMembers[] = (string)$member;
                }
            }

            $directBlockMembers = [];
            if (isset($entry->block->member)) {
                foreach ($entry->block->member as $member) {
                    $directBlockMembers[] = (string)$member;
                }
            }

            $combinedDirectPool = array_unique(array_merge($directAlertMembers, $directBlockMembers));
            $missingCategories = [];

            foreach ($masterCategories as $masterCategory) {
                if (!in_array($masterCategory, $combinedDirectPool)) {
                    $missingCategories[] = $masterCategory;
                }
            }

            // Make sure the <alert> block exists
            if (!isset($entry->alert)) {
                $entry->addChild('alert');
            }

            // --- ALPHABETICAL SORTING ENGINE ---
            // 1. Pool old items and newly found items together
            $allAlertMembers = array_merge($directAlertMembers, $missingCategories);

            // 2. Perform case-insensitive natural sorting on strings
            natcasesort($allAlertMembers);
            $allAlertMembers = array_values($allAlertMembers); // Re-index array keys

            // 3. Clear existing <member> elements inside the current <alert> block
            unset($entry->alert->member);

            // 4. Re-inject sorted entries sequentially
            foreach ($allAlertMembers as $sortedMember) {
                $entry->alert->addChild('member', PH::panosphp_htmlspecialchars($sortedMember));
            }
            // ------------------------------------

            // Collect credentials visibility metrics for summary
            $credAlert = isset($entry->{'credential-enforcement'}->alert->member) ? $entry->{'credential-enforcement'}->alert->member : [];
            $credBlock = isset($entry->{'credential-enforcement'}->block->member) ? $entry->{'credential-enforcement'}->block->member : [];
            $combinedCredPool = [];
            foreach($credAlert as $m) $combinedCredPool[] = (string)$m;
            foreach($credBlock as $m) $combinedCredPool[] = (string)$m;

            $missingCred = [];
            foreach ($masterCategories as $masterCategory) {
                if (!in_array($masterCategory, $combinedCredPool)) {
                    $missingCred[] = $masterCategory;
                }
            }

            $summary[$profileName] = [
                'added_to_alert' => $missingCategories,
                'still_missing_in_cred_enforcement' => $missingCred
            ];
        }

        // Save changes back to disk with multi-line formatting configuration
        if (!empty($summary)) {
            $dom = new DOMDocument('1.0');
            $dom->preserveWhiteSpace = false;
            $dom->formatOutput = true;
            $dom->loadXML($xml->asXML());

            $outputXml = $dom->saveXML($dom->documentElement);

            if ($hasTemporaryRoot) {
                $outputXml = preg_replace('/^<root[^>]*>/i', '', $outputXml);
                $outputXml = preg_replace('/<\/root>$/i', '', $outputXml);
                $outputXml = trim($outputXml);
            }

            file_put_contents($filePath, $outputXml);
        }

        return $summary;
    }
}