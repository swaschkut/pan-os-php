# HTML to XLS Merger script
# Designed to work with autoreporter.sh - ensure this file exists in the same directory as autoreporter.sh when run
# This script is intended to scan the output directories of autoreporter.sh and combine the HTML files into a single Excel workbook
# with multiple tabs for ease of reading.

try:
    import os, re
except ImportError:
	print("python import failure: 'os, re' NOT found")
	exit()

try:
    import pandas as pd
except ImportError:
	print("python import failure: 'pandas' NOT found")
	exit()

try:
    import sys
except ImportError:
	print("python import failure: 'sys' NOT found")
	exit()

try:
    from io import StringIO
except ImportError:
	print("python import failure: 'StringIO' from io NOT found")
	exit()

def sorted_directory_listing_with_os_scandir(directory):
    with os.scandir(directory) as entries:
        sorted_entries = sorted(entries, key=lambda entry: entry.name)
        sorted_items = [entry.name for entry in sorted_entries]
    return sorted_items

filepath = sys.argv[1]
if filepath.endswith('/'):
	filepath = filepath
else:
	filepath = sys.argv[1]+'/'

excelfilename = sys.argv[2]

cwd = os.path.dirname(filepath)

print("Found directory "+cwd)
excelfile = pd.ExcelWriter(f'{cwd}/{excelfilename}', engine='xlsxwriter')
print("Creating excel file "+str(excelfile)+" in directory "+cwd)
excelfile
with pd.ExcelWriter(excelfile) as writer:
    for file_str in sorted_directory_listing_with_os_scandir(cwd):
        if file_str.endswith('.html'):
            print("Found HTML file "+file_str+" in directory "+cwd)
            srcFile = cwd+"/"+file_str
            # Read HTML Files
            with open(srcFile, 'r') as src:
                html_file = src.read()
            # Clean the break characters and replace them with ", "
            breakStrip = html_file.replace('<br />',', ')
            cleaned_file = pd.read_html(StringIO(breakStrip))
            shortname=file_str.strip(".html")
            # Create worksheets per HTML file within the Excel File
            print("Stripping text from "+str(shortname)+". Worksheet name is "+shortname)
            for df in cleaned_file:
                print("Writing sheet "+shortname+" to workbook "+str(excelfilename))
                df.to_excel(writer, sheet_name=shortname)