import plotly.graph_objects as go
import numpy as np




# Daten: Logging zuerst, DNS Security zuletzt
categories = [
    "Logging", "Log Forwarding", "Wildfire", "Zone Protection",
    "App-ID", "User-ID", "Service/Port", "Antivirus Profiles", "Anti-Spyware Profiles",
    "Vulnerability Profiles", "File Blocking Profiles", "Data Filtering",
    "URL Filtering Profiles", "Credential Theft Prevention", "DNS Security"
]
values = [100, 35, 15, 67, 8, 0, 99, 80, 98, 98, 98, 0, 0, 0, 98]

# Reihenfolge anpassen
start_index = categories.index("Logging")
categories = categories[start_index:] + categories[:start_index]
values = values[start_index:] + values[:start_index]
theta = [i * (360 / len(categories)) for i in range(len(categories))]
average_value = round(np.mean(values), 1)

# 1️⃣ Ampel-Farben basierend auf Ziel-Erreichung
ampel_colors_full = []
for v in values:
    if v < 25:
        ampel_colors_full.append("rgba(255,0,0,1)")       # leichtes Rot
    elif v < 50:
        ampel_colors_full.append("rgba(255,165,0,1)")     # leichtes Orange
    elif v < 75:
        ampel_colors_full.append("rgba(255,255,0,1)")     # leichtes Gelb
    elif v <= 100:
        ampel_colors_full.append("rgba(0,125,0,1)")       # leichtes Grün
    else:
        ampel_colors_full.append("rgba(0,0,0,0)")           # vollständig = unsichtbar

# 1️⃣ Ampel-Farben halbtransparent
ampel_colors = []
for v in values:
    if v < 25:
        ampel_colors.append("rgba(255,0,0,0.2)")       # leichtes Rot
    elif v < 50:
        ampel_colors.append("rgba(255,165,0,0.2)")     # leichtes Orange
    elif v < 75:
        ampel_colors.append("rgba(255,255,0,0.2)")     # leichtes Gelb
    elif v <= 100:
        ampel_colors.append("rgba(0,255,0,0.2)")       # leichtes Grün
    else:
        ampel_colors.append("rgba(0,0,0,0)")           # vollständig = unsichtbar

# Werte skalieren
scaled_values = [0 + (v / 100) * 80 for v in values]

# Plot starten
fig = go.Figure()



# 3️⃣ HAUPTWERTE (Balken mit Verlauf)
fig.add_trace(go.Barpolar(
    r=scaled_values,
    theta=theta,
    text=[f"{cat}<br>{val}%" for cat, val in zip(categories, values)],
    marker=dict(
        color=ampel_colors_full,
        line_color='white',
        line_width=0
    ),
    hoverinfo='text',
    name='Adoption Rate'
))


# 2️⃣ Basisschicht (immer 100%)
fig.add_trace(go.Barpolar(
    base=0,
    r=[80] * 15,
    theta=theta,
    marker=dict(
        color=ampel_colors,
        line_color='white',
        line_width=0
    ),
    hoverinfo='skip',
    showlegend=False
))




circle_points = 200
theta_circle = np.linspace(0, 360, circle_points)

#for r_val in [20, 40, 60, 80, 100]:
for r_val in [20, 40, 60, 80]:
    fig.add_trace(go.Scatterpolar(
        r=[r_val] * circle_points,
        theta=theta_circle,
        mode='lines',
        line=dict(color='lightgray', width=1),  # oder 'gray', 'white', etc.
        hoverinfo='skip',
        showlegend=False
    ))

#for r_val in [20, 40, 60, 80, 100]:
for r_val in [80,99]:
    fig.add_trace(go.Scatterpolar(
        r=[r_val] * circle_points,
        theta=theta_circle,
        mode='lines',
        line=dict(color='black', width=1),  # oder 'gray', 'white', etc.
        hoverinfo='skip',
        showlegend=False
    ))

circle_points = 200
theta_circle = np.linspace(0, 360, circle_points)
r_circle = [1] * circle_points  # Radius der Maske – du kannst z.B. 40 oder 50 nehmen

fig.add_trace(go.Scatterpolar(
    r=r_circle,
    theta=theta_circle,
    mode='lines',
    fill='toself',
    fillcolor='white',
    #line_color='black',
    line=dict(color='black', width=1),  # oder 'gray', 'white', etc.
    hoverinfo='skip',
    showlegend=False
))


# 5️⃣ Text in der Mitte
fig.add_trace(go.Scatterpolar(
    r=[-60],
    theta=[0],
    mode='text',
    text=[f"Average<br><b>{average_value}%</b><br>Adoption<br>______________<br>{100-average_value}% Not Adopted"],
    textfont=dict(size=20, color='black'),
    hoverinfo='skip',
    showlegend=False,
    fillcolor="white"
))






# Layout finalisieren – HIER wurde die Hintergrundfarbe ergänzt ⬇️
fig.update_layout(
    title='Adoption Overview (Radial Heatmap)',
    polar=dict(
        bgcolor='white',  # 👈 HINZUGEFÜGT: Hintergrund für den Polarbereich
        radialaxis=dict(
            range=[-60, 100],
            showticklabels=False,
            ticks='',
            linewidth=0,
        ),
        angularaxis=dict(
            tickmode='array',
            tickvals=theta,
            ticktext=[f"<b>{cat}</b><br>({val}%)" for cat, val in zip(categories, values)],
            direction='clockwise',
            rotation=78,
            gridcolor='rgba(0,0,0,0)',   # <- entfernt die „Tortenstücke“-Linien
        )
    ),
    showlegend=False,
    template='plotly_white',
    margin=dict(t=100, b=100, l=50, r=50)
)



# Speichern
fig.write_image("radial_adoption_chart.png", width=1000, height=1000)

# Vorschau
fig.show()
