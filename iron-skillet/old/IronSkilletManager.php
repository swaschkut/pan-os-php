<?php

class IronSkilletManager {
    private $basePath;
    private $supportedVersions = [];
    private $fileStructure = [];

    /**
     * Constructor
     * @param string $basePath Path to the local iron-skillet directory clones from GitHub
     */
    public function __construct($basePath) {
        // Ensure trailing slash
        $this->basePath = rtrim($basePath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
    }

    /**
     * Scans the Iron-Skillet directory to find PAN-OS versions and their associated files.
     */
    public function scanRepository() {
        if (!is_dir($this->basePath)) {
            throw new Exception("The provided base path does not exist: " . $this->basePath);
        }

        // Iron-skillet structures folders by versions (e.g., v9.1, v10.0, v10.1, v11.0, etc.)
        $directories = scandir($this->basePath);

        foreach ($directories as $dir) {
            if ($dir === '.' || $dir === '..') continue;

            $fullPath = $this->basePath . $dir;

            // Check if directory matches a version pattern (e.g., starts with 'v' or is a version number)
            if (is_dir($fullPath) && (preg_match('/^v?\d+\.\d+/', $dir) || $dir === 'panos_v10.0' || $dir === 'panos_v11.0')) {
                $version = $dir;
                $this->supportedVersions[] = $version;
                $this->fileStructure[$version] = [
                    'alert' => [],
                    'best-practice' => []
                ];

                $this->scanVersionTemplates($fullPath, $version);
            }
        }
        return $this->fileStructure;
    }

    /**
     * Helper to scan specific template folders inside a PAN-OS version
     */
    private function scanVersionTemplates($versionPath, $version) {
        $iterator = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($versionPath));

        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'xml') {
                $filePath = $file->getRealPath();
                $fileName = $file->getFilename();

                // Determine if it belongs to alert profiles or best practices based on path or filename
                if (stripos($filePath, 'alert') !== false) {
                    $this->fileStructure[$version]['alert'][] = [
                        'name' => $fileName,
                        'path' => $filePath
                    ];
                } elseif (stripos($filePath, 'iron_skillet') !== false || stripos($filePath, 'best') !== false || stripos($filePath, 'profiles') !== false) {
                    $this->fileStructure[$version]['best-practice'][] = [
                        'name' => $fileName,
                        'path' => $filePath
                    ];
                }
            }
        }
    }

    /**
     * Gets the full list of parsed file structures grouped by version.
     */
    public function getFileStructure() {
        return $this->fileStructure;
    }

    /**
     * Compares an input array of required URL categories against existing profile files.
     * If any categories are missing from the files, it flags them or placeholders can be generated.
     * * @param array $requiredCategories Array of strings representing required URL categories.
     * @param string $version The specific PAN-OS version folder to audit.
     * @param string $type 'alert' or 'best-practice'
     * @return array Array containing 'existing', 'missing', and 'status'
     */
    public function auditAndSyncUrlCategories(array $requiredCategories, $version, $type = 'alert') {
        if (!isset($this->fileStructure[$version])) {
            return ['error' => "Version $version not found in scanned repository."];
        }

        $filesToCheck = $this->fileStructure[$version][$type];
        $foundCategories = [];
        $missingCategories = [];

        // Parse files to find which categories are already configured
        foreach ($filesToCheck as $fileInfo) {
            $xmlContent = file_get_contents($fileInfo['path']);
            if ($xmlContent === false) continue;

            // Use simple XML or Regex to find categories inside the templates dynamically
            // (Iron-skillet utilizes snippets that hold custom URL categories or profiles)
            foreach ($requiredCategories as $category) {
                if (stripos($xmlContent, $category) !== false) {
                    if (!in_array($category, $foundCategories)) {
                        $foundCategories[] = $category;
                    }
                }
            }
        }

        // Determine what is missing
        foreach ($requiredCategories as $category) {
            if (!in_array($category, $foundCategories)) {
                $missingCategories[] = $category;
            }
        }

        // Auto-add logic: If category is missing, create/append a stub block or add it to your profile definitions
        if (!empty($missingCategories)) {
            $this->addMissingCategoriesToTemplates($missingCategories, $version, $type);
        }

        return [
            'version' => $version,
            'type' => $type,
            'existing_categories' => $foundCategories,
            'missing_categories_added' => $missingCategories,
            'synced' => empty($missingCategories) ? true : false
        ];
    }

    /**
     * Handles adding missing categories directly to configuration templates
     */
    private function addMissingCategoriesToTemplates(array $missingCategories, $version, $type) {
        // Find the target profile configuration file to append to (e.g., url-category snippets)
        $targetFile = null;
        foreach ($this->fileStructure[$version][$type] as $fileInfo) {
            if (stripos($fileInfo['name'], 'url') !== false || stripos($fileInfo['name'], 'profile') !== false) {
                $targetFile = $fileInfo['path'];
                break;
            }
        }

        // Fallback to the first available file if no specific URL file was found
        if (!$targetFile && !empty($this->fileStructure[$version][$type])) {
            $targetFile = $this->fileStructure[$version][$type][0]['path'];
        }

        if ($targetFile && is_writable($targetFile)) {
            $xml = simplexml_load_file($targetFile);

            if ($xml !== false) {
                foreach ($missingCategories as $category) {
                    // Create XML nodes dynamically depending on your pan-os-php structure requirements
                    // Example adds an entry tag under a list/member block if applicable
                    if (isset($xml->member)) {
                        $xml->addChild('member', PH::panosphp_htmlspecialchars($category));
                    } else {
                        $entry = $xml->addChild('entry');
                        $entry->addAttribute('name', PH::panosphp_htmlspecialchars($category));
                    }
                }
                // Save updated file back to disk
                $xml->asXML($targetFile);
            }
        }
    }
}