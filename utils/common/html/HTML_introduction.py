import json
import re
import os
import sys
from bs4 import BeautifulSoup

def extract_filename(action_string):
    """Extracts 'FILENAME.html' from 'actions=exportToExcel:FILENAME.html'"""
    match = re.search(r'exportToExcel:([^, ]+\.html)', action_string)
    return match.group(1) if match else None

def count_instances_in_file(folder_path, filename):
    """Parses the generated HTML file in the project folder to count data rows."""
    file_path = os.path.join(folder_path, filename)
    if not os.path.exists(file_path):
        return 0
    
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            soup = BeautifulSoup(f, 'html.parser')
            # Count rows and subtract 1 for the header
            rows = soup.find_all('tr')
            return max(0, len(rows) - 1)
    except Exception:
        return 0

def main():
    # Validate arguments: script path, project path, filename, json file
    if len(sys.argv) < 4:
        print('Usage: python generate_report.py "projectfolderpath" "filename" visibility_assessment.json')
        sys.exit(1)

    project_folder = sys.argv[1]
    output_filename = sys.argv[2]
    json_config_path = sys.argv[3]

    # Ensure output filename has .html extension
    if not output_filename.endswith('.html'):
        output_filename += '.html'

    # Check if JSON exists
    if not os.path.exists(json_config_path):
        print(f"Error: JSON file '{json_config_path}' not found.")
        sys.exit(1)

    # Load JSON data
    with open(json_config_path, 'r') as f:
        data = json.load(f)

    # HTML Template mimicking the original style
    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <style>
            .ritz .waffle {{ border-collapse: collapse; width: 100%; }}
            body {{ font-family: 'Arial', sans-serif; margin: 20px; }}
            .s0 {{ background-color: #000000; color: #ffffff; padding: 5px; font-size: 10pt; border: 1px solid #000; }}
            .s8 {{ background-color: #b0b3b2; font-weight: bold; font-size: 8pt; border: 1px solid #000; padding: 3px; text-align: left; }}
            .s9 {{ background-color: #d4d4d4; font-weight: bold; font-size: 8pt; border: 1px solid #000; padding: 3px; }}
            .s11 {{ background-color: #ffffff; font-size: 8pt; border: 1px solid #000; padding: 3px; vertical-align: top; }}
            .critical {{ background-color: #ff0000; }}
            .low {{ background-color: #ffff00; }}
        </style>
    </head>
    <body>
        <table class="waffle">
            <tr>
                <td class="s0" colspan="5">This sheet explains how to utilize this documentation. Below listed table give a list of sheets, along with the explanation regarding the filters used &amp; the action needed to remediate the issue. We recommend to prioritize the tasks based on their criticality.</td>
            </tr>
            <tr>
                <td class="s8">Sheet Name</td>
                <td class="s8">Number of Instances</td>
                <td class="s8">Explanation</td>
                <td class="s8">Action Needed</td>
                <td class="s8">Criticality</td>
            </tr>
            {rows}
        </table>
    </body>
    </html>
    """

    rows_content = ""
    for cmd in data.get("command", []):
        action_str = cmd.get("actions", "")
        
        # Process entries containing an Excel/HTML export
        if "exportToExcel" in action_str:
            sheet_name = extract_filename(action_str)
            if not sheet_name:
                continue

            # Calculate instances from the actual file in the project folder
            instances = count_instances_in_file(project_folder, sheet_name)
            
            # Map dynamic merger fields from JSON
            explanation = cmd.get("html-merger-explanation", "")
            action_needed = cmd.get("html-merger-action-needed", "")
            severity = cmd.get("html-merger-severity", "")
            
            # Apply styling for Critical/Low severity
            sev_style = ""
            if severity.lower() == "critical": sev_style = 'class="s11 critical"'
            elif severity.lower() == "low": sev_style = 'class="s11 low"'
            else: sev_style = 'class="s11"'

            rows_content += f"""
            <tr>
                <td class="s9">{sheet_name}</td>
                <td class="s11">{instances}</td>
                <td class="s11">{explanation}</td>
                <td class="s11">{action_needed}</td>
                <td {sev_style}>{severity}</td>
            </tr>
            """

    # Ensure the project folder exists
    os.makedirs(project_folder, exist_ok=True)
    
    # Save the file to the specified path
    final_path = os.path.join(project_folder, output_filename)
    with open(final_path, 'w', encoding='utf-8') as f:
        f.write(html_template.format(rows=rows_content))

    print(f"Report successfully saved to: {final_path}")

if __name__ == "__main__":
    main()