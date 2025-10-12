import os
import time
import base64
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
# New Imports for robust waiting
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC

def generate_and_save_charts(html_file_path):
    """
    Automates the chart generation, reads the base64 data, and saves
    the files as JPGs in a 'jpg' folder.
    """
    # --- Setup Directories ---
    current_dir = os.path.dirname(os.path.abspath(__file__))
    output_dir = os.path.join(current_dir, "jpg")

    # Create the output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # --- Setup Chrome Options ---
    chrome_options = Options()

    # **CRITICAL FIX:** Read driver and browser paths from environment variables
    # guaranteed to be set by the selenium/standalone-chromium base image.
    chrome_driver_path = os.environ.get('CHROMEDRIVER_PATH', '/usr/bin/chromedriver')
    chrome_binary_path = os.environ.get('CHROME_BIN', '/usr/bin/chromium')

    # Explicitly set the browser binary location
    chrome_options.binary_location = chrome_binary_path

    # Run in headless mode (no visible browser window) for automation.
    chrome_options.add_argument("--headless")
    chrome_options.add_argument("--disable-gpu")
    chrome_options.add_argument("--no-sandbox")
    chrome_options.add_argument("--window-size=1200,800")
    chrome_options.add_argument("--disable-dev-shm-usage")

    prefs = {'profile.default_content_setting_values.automatic_downloads': 1}
    chrome_options.add_experimental_option("prefs", prefs)


    # --- Initialize WebDriver ---
    try:
        driver_service = Service(executable_path=chrome_driver_path)
        driver = webdriver.Chrome(service=driver_service, options=chrome_options)
    except Exception as e:
        print(f"Failed to initialize WebDriver. The Selenium container should have set the environment variables correctly. Error: {e}")
        return


    try:
        # --- Navigate to the local HTML file ---
        driver.get(f"file://{html_file_path}")
        print("Page opened successfully.")

        # --- Trigger the chart generation and data capture ---
        try:
            print("Waiting for 'Generate all JPGs' button to become present...")

            # CRITICAL FIX: The button was being searched by a non-existent ID.
            # Now, it is searched by its exact visible text content using XPath.
            wait = WebDriverWait(driver, 90) # Wait up to 10 seconds
            generate_button = wait.until(
                EC.presence_of_element_located((By.XPATH, "//button[text()='Generate all JPGs']"))
            )

            print("Found 'Generate all JPGs' button. Clicking...")
            generate_button.click()

            # Wait for all charts to be generated and data stored in the array
            print("Waiting for charts to be generated and data to be captured...")
            time.sleep(12)
            print("Finished waiting. Now processing captured data...")

        except Exception as e:
            # If a timeout occurs (element not found in 10s), the specific error will be printed here.
            print(f"An error occurred while trying to find or click the button: {e}")
            return

        # --- Get the base64 data from the browser's window object ---
        charts_data = driver.execute_script("return window.allChartsData;")

        if charts_data:
            print(f"Found {len(charts_data)} charts to save.")
            for chart in charts_data:
                file_name = chart['name']
                data_url = chart['data']

                # Decode the base64 string
                if ',' in data_url:
                    header, encoded_data = data_url.split(',', 1)
                    decoded_data = base64.b64decode(encoded_data)
                else:
                    print(f"Error: Invalid data URL format for {file_name}")
                    continue

                # Save the decoded data to a file
                file_path = os.path.join(output_dir, file_name)
                with open(file_path, "wb") as f:
                    f.write(decoded_data)
                print(f"Saved '{file_name}' to '{output_dir}'.")
        else:
            print("No chart data was captured.")

    finally:
        # --- Clean up ---
        driver.quit()
        print("WebDriver closed.")

if __name__ == "__main__":
    current_script_dir = os.path.dirname(os.path.abspath(__file__))
    html_file = 'temp_diagram.html'
    html_full_path = os.path.join(current_script_dir, html_file)

    if os.path.exists(html_full_path):
        print(f"Starting chart generation and file saving from {html_full_path}")
        generate_and_save_charts(html_full_path)
    else:
        print(f"Error: The file '{html_file}' was not found at '{html_full_path}'.")
