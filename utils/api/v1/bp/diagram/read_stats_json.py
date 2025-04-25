import json

# Datei laden
with open("test_stats_file.json", "r", encoding="utf-8") as file:
    data = json.load(file)

# Zugriff auf die "statistic"-Sektion
statistics = data["statistic"][0]

# Initialisierung
adoption = {}
visibility = {}
best_practice = {}

# Durchlaufe alle Statistik-Einträge
for stat in statistics:
    if isinstance(stat, dict) and "percentage" in stat:
        adoption = stat["percentage"].get("adoption", {})
        visibility = stat["percentage"].get("visibility", {})
        best_practice = stat["percentage"].get("best-practice", {})
        break  # Sobald gefunden, beenden

# Ausgabe
print("Adoption:", adoption)
print("Visibility:", visibility)
print("Best Practice:", best_practice)
