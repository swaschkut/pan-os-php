import json
import re
import os
import sys
from bs4 import BeautifulSoup

def extract_filename(action_string):
    """Extracts 'FILENAME.html' from 'actions=exportToExcel:FILENAME.html'"""
    match = re.search(r'exportToExcel:([^, ]+\.html)', action_string)
    return match.group(1) if match else None

def count_instances_in_file(filename):
    """Parses the generated HTML file to count data rows in its table."""
    if not os.path.exists(filename):
        return 0
    
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            soup = BeautifulSoup(f, 'html.parser')
            # Finds all table rows (tr)
            rows = soup.find_all('tr')
            # Subtract 1 to account for the header row
            return max(0, len(rows) - 1)
    except Exception:
        return 0

def main():
    # Check if the JSON filename was provided as an argument
    if len(sys.argv) < 2:
        print("Usage: python generate_report.py <config_file.json>")
        sys.exit(1)

    json_file_path = sys.argv[1]
    output_html_path = "Introduction_Report.html"

    if not os.path.exists(json_file_path):
        print(f"Error: File '{json_file_path}' not found.")
        sys.exit(1)

    # Load the JSON data dynamically
    with open(json_file_path, 'r') as f:
        data = json.load(f)

    # CSS and HTML structure based on the provided Introduction.html
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: 'Arial', sans-serif; margin: 20px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            .header-cell {{ background-color: #000; color: #fff; padding: 10px; font-size: 10pt; }}
            th {{ background-color: #b0b3b2; border: 1px solid #000; padding: 5px; font-size: 8pt; text-align: left; }}
            td {{ border: 1px solid #000; padding: 5px; font-size: 8pt; vertical-align: top; }}
            .sheet-name {{ background-color: #d4d4d4; font-weight: bold; }}
            .critical {{ background-color: #ff0000; }}
            .low {{ background-color: #ffff00; }}
        </style>
    </head>
    <body>
        <table>
            <tr><td colspan="5" class="header-cell">This sheet explains how to utilize this documentation. Below listed table give a list of sheets, along with the explanation regarding the filters used &amp; the action needed to remediate the issue.</td></tr>
            <thead>
                <tr>
                    <th>Sheet Name</th>
                    <th>Number of Instances</th>
                    <th>Explanation</th>
                    <th>Action Needed</th>
                    <th>Criticality</th>
                </tr>
            </thead>
            <tbody>
                {rows}
            </tbody>
        </table>
    </body>
    </html>
    """

    rows_content = ""
    for cmd in data.get("command", []):
        action_str = cmd.get("actions", "")
        # Filter for commands that generate individual HTML sheets
        if "exportToExcel" in action_str:
            filename = extract_filename(action_str)
            if not filename:
                continue

            # Calculate instances from the physical file
            instances = count_instances_in_file(filename)
            
            # Extract metadata if available, otherwise leave blank
            explanation = cmd.get("html-merger-explanation", "")
            action_needed = cmd.get("html-merger-action-needed", "")
            severity = cmd.get("html-merger-severity", "")
            
            # Handle severity styling
            sev_class = severity.lower() if severity.lower() in ['critical', 'low'] else ""

            rows_content += f"""
            <tr>
                <td class="sheet-name">{filename}</td>
                <td>{instances}</td>
                <td>{explanation}</td>
                <td>{action_needed}</td>
                <td class="{sev_class}">{severity}</td>
            </tr>
            """

    # Create the final HTML
    with open(output_html_path, 'w', encoding='utf-8') as f:
        f.write(html_template.format(rows=rows_content))

    print(f"Successfully generated {output_html_path} using {json_file_path}")

if __name__ == "__main__":
    main()