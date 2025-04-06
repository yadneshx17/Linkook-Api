# result_writer.py

import os
import logging
from typing import Dict, Any


class ResultWriter:
    """
    ResultWriter handles writing scan results to various file formats such as TXT, CSV, and Excel (XLSX).
    """

    def __init__(self, output_dir: str):
        """
        Initialize the ResultWriter with the specified output directory.

        :param output_dir: Directory where result files will be saved.
        """
        self.output_dir = output_dir
        self.ensure_output_directory()

    def ensure_output_directory(self):
        """
        Create the output directory if it does not exist.
        """
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)
            logging.info(f"Created output directory at: {self.output_dir}")
        else:
            logging.debug(f"Output directory already exists at: {self.output_dir}")

    def write_txt(self, username: str, results: Dict[str, Dict[str, Any]]):
        """
        Write scan results to a TXT file.

        :param username: The username being scanned.
        :param results: A dictionary containing scan results for each site.
        """
        result_file = os.path.join(self.output_dir, f"{username}.txt")
        try:
            with open(result_file, "w", encoding="utf-8") as file:
                file.write(f"Results for username: {username}\n\n")
                found_counter = 0
                for site, data in results.items():
                    status = "FOUND" if data["found"] else "NOT FOUND"
                    file.write(f"Site: {site}\n")
                    file.write(f"Profile URL: {data['profile_url']}\n")
                    file.write(f"Status: {status}\n")

                    if data["found"] and "other_links" in data and data["other_links"]:
                        file.write("Linked Accounts:\n")
                        for provider, urls in data["other_links"].items():
                            if isinstance(urls, list):
                                urls_str = ", ".join(urls)
                            else:
                                urls_str = urls
                            file.write(f"- {provider}: {urls_str}\n")

                    if data["error"]:
                        file.write(f"Error: {data['error']}\n")
                    file.write("\n")
                    if data["found"]:
                        found_counter += 1
                # file.write(f"Total Websites Username Detected On: {found_counter}\n")
            print(f"\nSaved result for {username} to {result_file}")
        except Exception as e:
            logging.error(f"Failed to write TXT results for {username}: {e}")

    def should_print_not_found(self) -> bool:
        """
        Determine if 'not found' results should be printed based on user preference.

        :return: True if 'not found' results should be included, False otherwise.
        """
        # This method can be customized based on user input or configuration.
        # For this example, we'll assume it's controlled elsewhere.
        # You might pass this as a parameter during initialization.
        return True  # Placeholder implementation
