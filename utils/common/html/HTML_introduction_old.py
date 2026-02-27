import json
import re
import os
from bs4 import BeautifulSoup

def extract_filename(action_string):
    """Extracts 'FILENAME.html' from 'actions=exportToExcel:FILENAME.html'"""
    # Look for exportToExcel: followed by a filename ending in .html
    match = re.search(r'exportToExcel:([^, ]+\.html)', action_string)
    return match.group(1) if match else None

def count_instances_in_file(filename):
    """Parses the generated HTML file to count data rows in its table."""
    if not os.path.exists(filename):
        return "File not found"

    try:
        with open(filename, 'r', encoding='utf-8') as f:
            soup = BeautifulSoup(f, 'html.parser')
            # Assuming the exported files contain a <table> with a <tbody>
            # We count rows (tr) but usually skip the first one if it's a header
            rows = soup.find_all('tr')
            if not rows:
                return 0
            # Adjust the count by -1 if the file includes a header row
            return max(0, len(rows) - 1)
    except Exception as e:
        return f"Error: {str(e)}"

def generate_html(json_file_path, output_html_path):
    # Load the JSON assessment configuration
    with open(json_file_path, 'r') as f:
        data = json.load(f)

    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            body {{ font-family: 'Arial', sans-serif; margin: 20px; color: #000; }}
            table {{ border-collapse: collapse; width: 100%; font-size: 8pt; }}
            th {{ background-color: #b0b3b2; font-weight: bold; border: 1px solid #000; padding: 3px; text-align: left; }}
            td {{ border: 1px solid #000; padding: 3px; vertical-align: top; word-wrap: break-word; }}
            .header {{ background-color: #000; color: #ffffff; padding: 10px; font-size: 10pt; margin-bottom: 15px; }}
            .sheet-name {{ background-color: #d4d4d4; font-weight: bold; }}
            .critical {{ background-color: #ff0000; }}
            .low {{ background-color: #ffff00; }}
            .info {{ background-color: #34a853; }}
        </style>
    </head>
    <body>
        <div class="header">
            This sheet explains how to utilize this documentation. Below listed table give a list of sheets,
            along with the explanation regarding the filters used &amp; the action needed to remediate the issue.
        </div>
        <table>
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

    rows_html = ""
    # Iterate through commands defined in visibility_assessment.json
    for cmd in data.get("command", []):
        action_str = cmd.get("actions", "")
        if "exportToExcel" in action_str:
            sheet_name = extract_filename(action_str)
            if not sheet_name:
                continue

            # Calculate instances by reading the physical file
            instance_count = count_instances_in_file(sheet_name)

            # Map dynamic merger fields from JSON
            explanation = cmd.get("html-merger-explanation", "")
            action = cmd.get("html-merger-action-needed", "")
            severity = cmd.get("html-merger-severity", "")

            # Assign CSS classes based on severity
            sev_class = ""
            if severity.lower() == "critical": sev_class = 'class="critical"'
            elif severity.lower() == "low": sev_class = 'class="low"'
            elif severity.lower() == "informational": sev_class = 'class="info"'

            rows_html += f"""
                <tr>
                    <td class="sheet-name">{sheet_name}</td>
                    <td style="text-align: center;">{instance_count}</td>
                    <td>{explanation}</td>
                    <td>{action}</td>
                    <td {sev_class}>{severity}</td>
                </tr>
            """

    # Format the template with generated rows
    final_output = html_template.format(rows=rows_html)

    with open(output_html_path, 'w', encoding='utf-8') as f:
        f.write(final_output)

    print(f"Report generated successfully: {output_html_path}")

if __name__ == "__main__":
    # Ensure BeautifulSoup is installed: pip install beautifulsoup4
    generate_html('visibility_assessment.json', 'Final_Assessment_Report.html')