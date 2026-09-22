<?php

class IronSkilletManager {
    private $basePath;
    private $supportedVersions = [];
    private $fileStructure = [];
    private $predefinedXmlPath;

    /**
     * Constructor
     * @param string $basePath Path to the local iron-skillet directory
     * @param string $predefinedXmlPath Path or URL to the predefined.xml file
     */
    public function __construct($basePath, $predefinedXmlPath) {
        $this->basePath = rtrim($basePath, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR;
        $this->predefinedXmlPath = $predefinedXmlPath;
    }

    /**
     * Reads and parses URL categories from the predefined.xml file
     * XML Path: /predefined/pan-url-categories
     * * @return array List of valid URL categories
     */
    public function getPredefinedUrlCategories() {
        // Load the XML file (supports local paths or remote URLs if allow_url_fopen is enabled)
        $xmlContent = @file_get_contents($this->predefinedXmlPath);
        if ($xmlContent === false) {
            throw new Exception("Could not load predefined.xml from: " . $this->predefinedXmlPath);
        }

        $xml = simplexml_load_string($xmlContent);
        if ($xml === false) {
            throw new Exception("Failed to parse predefined.xml structure.");
        }

        $categories = [];

        // Navigate to /predefined/pan-url-categories
        if (isset($xml->{'pan-url-categories'})) {
            // Adjusting based on standard PAN-OS XML layout (usually <entry name="category-name">)
            foreach ($xml->{'pan-url-categories'}->entry as $entry) {
                if (isset($entry['name'])) {
                    $categories[] = (string)$entry['name'];
                }
            }
        }

        // If the structure is slightly different (e.g., straight members instead of entries)
        if (empty($categories) && isset($xml->{'pan-url-categories'}->member)) {
            foreach ($xml->{'pan-url-categories'}->member as $member) {
                $categories[] = (string)$member;
            }
        }

        return $categories;
    }

    /**
     * Scans the Iron-Skillet directory to map PAN-OS versions and their associated files.
     */
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
                    'alert' => [],
                    'best-practice' => []
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
                $filePath = $file->getRealPath();
                $fileName = $file->getFilename();

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
     * Compares the predefined URL categories array against existing profile files.
     */
    public function auditAndSyncUrlCategories(array $requiredCategories, $version, $type = 'alert') {
        if (!isset($this->fileStructure[$version])) {
            return ['error' => "Version $version not found in scanned repository."];
        }

        $filesToCheck = $this->fileStructure[$version][$type];
        $foundCategories = [];
        $missingCategories = [];

        foreach ($filesToCheck as $fileInfo) {
            $xmlContent = file_get_contents($fileInfo['path']);
            if ($xmlContent === false) continue;

            foreach ($requiredCategories as $category) {
                // Perform accurate word matching or XML attribute matching to avoid partial substring hits
                if (preg_match('/[\'"]' . preg_quote($category, '/') . '[\'"]|>' . preg_quote($category, '/') . '</i', $xmlContent)) {
                    if (!in_array($category, $foundCategories)) {
                        $foundCategories[] = $category;
                    }
                }
            }
        }

        foreach ($requiredCategories as $category) {
            if (!in_array($category, $foundCategories)) {
                $missingCategories[] = $category;
            }
        }

        if (!empty($missingCategories)) {
            $this->addMissingCategoriesToTemplates($missingCategories, $version, $type);
        }

        return [
            'version' => $version,
            'type' => $type,
            'total_predefined_checked' => count($requiredCategories),
            'existing_categories' => $foundCategories,
            'missing_categories_added' => $missingCategories,
            'synced' => empty($missingCategories)
        ];
    }

    private function addMissingCategoriesToTemplates(array $missingCategories, $version, $type) {
        $targetFile = null;
        foreach ($this->fileStructure[$version][$type] as $fileInfo) {
            if (stripos($fileInfo['name'], 'url') !== false || stripos($fileInfo['name'], 'profile') !== false) {
                $targetFile = $fileInfo['path'];
                break;
            }
        }

        if (!$targetFile && !empty($this->fileStructure[$version][$type])) {
            $targetFile = $this->fileStructure[$version][$type][0]['path'];
        }

        if ($targetFile && is_writable($targetFile)) {
            $xml = simplexml_load_file($targetFile);

            if ($xml !== false) {
                // Attempts to append missing profiles where elements belong
                foreach ($missingCategories as $category) {
                    if (isset($xml->member)) {
                        $xml->addChild('member', PH::panosphp_htmlspecialchars($category));
                    } else {
                        $entry = $xml->addChild('entry');
                        $entry->addAttribute('name', PH::panosphp_htmlspecialchars($category));
                    }
                }
                $xml->asXML($targetFile);
            }
        }
    }

    /**
     * Parses a profile XML file/snippet and extracts profiles, sub-sections, and members.
     * Handles both valid root XMLs and fragmented multi-entry blocks by wrap-protection.
     * * @param string $filePath Path to the target XML profile file
     * @return array Structured data of profiles found inside the file
     */
    public function parseUrlProfilesFromFile($filePath) {
        $content = file_get_contents($filePath);
        if (!$content) return [];

        // Iron-skillet files sometimes miss a single global root element if they are raw snippets.
        // Wrapping ensures SimpleXML parses it flawlessly.
        if (strpos(trim($content), '<root>') === false) {
            $content = '<root>' . $content . '</root>';
        }

        $xml = @simplexml_load_string($content);
        if ($xml === false) return [];

        $profiles = [];

        // Target every <entry> block (e.g., Outbound-URL, Alert-Only-URL, Exception-URL)
        foreach ($xml->xpath('//entry') as $entry) {
            $profileName = (string)$entry['name'];
            if (empty($profileName)) continue;

            $profiles[$profileName] = [
                'direct_sections' => [],
                'credential_enforcement' => []
            ];

            // 1. Direct structural sub-sections (<alert>, <block>, etc.)
            foreach ($entry->children() as $key => $child) {
                if ($key === 'credential-enforcement') continue; // Handled separately below

                if (isset($child->member)) {
                    foreach ($child->member as $member) {
                        $profiles[$profileName]['direct_sections'][$key][] = (string)$member;
                    }
                }
            }

            // 2. Nested <credential-enforcement> sub-sections
            if (isset($entry->{'credential-enforcement'})) {
                foreach ($entry->{'credential-enforcement'}->children() as $subKey => $subChild) {
                    if (isset($subChild->member)) {
                        foreach ($subChild->member as $member) {
                            $profiles[$profileName]['credential_enforcement'][$subKey][] = (string)$member;
                        }
                    }
                }
            }
        }

        return $profiles;
    }

    /**
     * Exposes the structural array mapped during scanRepository()
     */
    public function getVersions() {
        return array_keys($this->fileStructure);
    }
}