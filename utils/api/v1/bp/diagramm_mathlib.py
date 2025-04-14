import matplotlib.pyplot as plt
import numpy as np

# Daten vorbereiten
categories = [
    "Logging", "Log Forwarding", "Wildfire", "Zone Protection",
    "App-ID", "User-ID", "Service/Port", "Antivirus Profiles", "Anti-Spyware Profiles",
    "Vulnerability Profiles", "File Blocking Profiles", "Data Filtering",
    "URL Filtering Profiles", "Credential Theft Prevention", "DNS Security"
]
values = [100, 35, 15, 67, 8, 0, 99, 80, 98, 98, 98, 0, 0, 0, 98]

# Kategorien rotieren
start_index = categories.index("Logging")
categories = categories[start_index:] + categories[:start_index]
values = values[start_index:] + values[:start_index]

# Farben definieren
def ampel_color(v, alpha=1.0):
    if v < 25:
        return (1.0, 0, 0, alpha)  # Rot
    elif v < 50:
        return (1.0, 165/255, 0, alpha)  # Orange
    elif v < 75:
        return (1.0, 1.0, 0, alpha)  # Gelb
    else:
        return (0, 125/255, 0, alpha)  # Grün

colors_full = [ampel_color(v, alpha=1.0) for v in values]
colors_base = [ampel_color(v, alpha=0.2) for v in values]

# Skalierte Werte
scaled_values = [0 + (v / 100) * 0.8 for v in values]
N = len(categories)
angles = np.linspace(0, 2 * np.pi, N, endpoint=False)

# Plot
fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(polar=True))
ax.set_theta_direction(-1)
ax.set_theta_offset(np.pi / 2.5)
ax.set_facecolor("white")

# Hintergrundringe
for r in [0.2, 0.4, 0.6, 0.8]:
    ax.plot(np.linspace(0, 2*np.pi, 200), [r]*200, color='lightgray', lw=1)

# Hauptbalken
bars = ax.bar(angles, scaled_values, width=2*np.pi/N, color=colors_full, edgecolor='white', linewidth=0)

# Basis-Schicht
ax.bar(angles, [0.8]*N, width=2*np.pi/N, color=colors_base, edgecolor='white', linewidth=0, bottom=0)

# Kategorie-Texte
for angle, label, val in zip(angles, categories, values):
    angle_deg = np.degrees(angle)
    rotation = angle_deg if angle_deg <= 180 else angle_deg - 180
    ha = 'left' if angle_deg <= 180 else 'right'
    ax.text(angle, 0.85, f"{label}\n({val}%)", ha=ha, va='center',
            rotation=rotation, rotation_mode='anchor', fontsize=8)

# Text im Zentrum
avg_val = round(np.mean(values), 1)
center_text = f"Average\n{avg_val}%\nAdoption\n–––––––––––\n{100 - avg_val}% Not Adopted"
ax.text(0, 0, center_text, ha='center', va='center', fontsize=12, weight='bold', color='black')

# Achsen ausblenden
ax.set_yticklabels([])
ax.set_xticklabels([])
ax.set_ylim(0, 1)

plt.title("Adoption Overview (Radial Heatmap)", fontsize=16, pad=30)
plt.tight_layout()
plt.savefig("radial_adoption_chart_matplotlib.png", dpi=300)
plt.show()
