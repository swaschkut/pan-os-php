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
    from bs4 import BeautifulSoup
    import xlsxwriter
except:
    print("python import failure: 'bs4' NOT found")
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

#cwd = "./"

#print("Found directory "+cwd)

elements = []

for file_str in sorted_directory_listing_with_os_scandir(cwd):
    if file_str.endswith('.html'):
        print("Found HTML file "+file_str+" in directory "+cwd)
        srcFile = cwd+"/"+file_str
        # Read HTML Files
        print(srcFile)
        html_file = None
        with open(srcFile, 'r') as src:
            html_file = src.read()
            print(f"File read complete for file: {srcFile}")
        # Clean the break characters and replace them with ", "
        ##bs4 for html parsing
        soup = BeautifulSoup(html_file, features='lxml')
        ## Extract Tables
        table = soup.find('table')
        table_found = "Not Found"
        if table and len(table):
            table_found = "Found"
        print(f"Table status: {table_found}")

        header = []
        rows = []
        for i, row in enumerate(table.find_all('tr')):
            if i == 0:
                header = [el.text.strip() for el in row.find_all('th')]
            else:
                rows.append([el.text.strip() for el in row.find_all('td')])
        cache = {}
        cache["header"] = header
        cache["rows"] = rows
        cache["file_str"] = file_str
        elements.append(cache)

workbook = xlsxwriter.Workbook(filepath+excelfilename)
for element in elements:
    file_str = element.get("file_str")
    worksheet = workbook.add_worksheet(file_str.replace(".html", ''))
    worksheet.write_row(0, 0, element.get("header"))
    for i, row in enumerate(element.get("rows")):
        worksheet.write_row(i+1, 0, row)
    print(f"Table written into Excel with name: {file_str}")
workbook.close()
#print(filepath+excelfilename)