### Cache Deception Scanner
A Burp Suite extension for detecting cache deception vulnerabilities in web applications.

###### Latest version: 1.2

#### Overview

The **Cache Deception Scanner** is a Burp Suite extension designed to help security researchers and penetration testers identify cache deception vulnerabilities. This extension provides a custom request editor tab to visualize and analyze HTTP traffic for indicators of cache deception. Version 1.2 includes modular code structure for better maintainability, improved vulnerability detection through detailed header analysis (e.g., Cache-Control directives, CDN-specific headers), and structured HTTP editors for clearer request/response viewing.

#### Features

- Custom request editor tab for analyzing HTTP requests and responses with structured HTTP editors.
- Automated passive detection of cache deception issues, including score-based analysis of caching headers (e.g., max-age > 0, cache-status: hit).
- Clean interface with detailed vulnerability information, including reasons for detection (e.g., "Cache-Control: max-age=30").
- Modular codebase for easier extension and maintenance.

#### Installation

###### Option 1: Download Pre-built JAR (Recommended)

1. Visit the [Releases](https://github.com/Nowafen/cache-deception-scanner/releases) section of this repository.
2. Download the latest `WCDScanner-1.2.jar` file.
3. Open Burp Suite and navigate to the **Extender** tab.
4. Click **Add**, select **Java** as the extension type, and choose the downloaded `WCDScanner-1.2.jar`.
5. Click **Next** to load the extension.

###### Option 2: Build from Source

1. Clone the repository:
   ```bash
   git clone https://github.com/Nowafen/cache-deception-scanner.git
   cd cache-deception-scanner
   ```
2. Build using Gradle:
   ```bash
   gradle build
   ```
3. The compiled `WCDScanner-1.2.jar` file will be located at:
   ```
   build/libs/WCDScanner-1.2.jar
   ```
4. Load the JAR file into Burp Suite as described in Option 1.

#### Usage

After loading the extension, a new tab titled **WCD Scanner** will appear in the Burp Suite tabs.

- Send or forward requests to Burp Suite (e.g., from Proxy, Repeater, or Intruder).
- The extension will analyze requests and highlight potential cache deception issues in the table (e.g., "vulnerable packet" in the Vulnerable column).
- Click on a row in the table to view the full request and response in the structured editors below, including headers and body.
- Use the domain tree to filter by domain and view actions like deleting packets.

For more details, check the [source code](https://github.com/Nowafen/cache-deception-scanner) or contact the maintainer.
