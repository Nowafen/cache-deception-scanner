### Cache Deception Scanner
A Burp Suite extension for detecting cache deception vulnerabilities in web applications.
###### Latest version: 1.1

#### Overview

The **Cache Deception Scanner** is a Burp Suite extension designed to help security researchers and penetration testers identify cache deception vulnerabilities. This extension provides a custom request editor tab to visualize and analyze HTTP traffic for indicators of cache deception.

#### Features

- Custom request editor tab for analyzing HTTP requests.
- Automated passive detection of cache deception issues.
- Clean interface with detailed vulnerability information.

#### Installation

###### Option 1: Download Pre-built JAR (Recommended)

1. Visit the [Releases](https://github.com/Nowafen/cache-deception-scanner/releases) section of this repository.
2. Download the latest `wcd.jar` file.
3. Open Burp Suite and navigate to the **Extender** tab.
4. Click **Add**, select **Java** as the extension type, and choose the downloaded `WCDScanner-v.v.jar`.
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
3. The compiled `WCDScanner-v.v.jar` file will be located at:
   ```
   build/libs/WCDScanner-1.1.jar
   ```
4. Load the JAR file into Burp Suite as described in Option 1.

#### Usage

After loading the extension, a new tab titled **Cache Deception Scanner** will appear in the HTTP request editor.

- Send or forward requests to Burp Suite.
- The extension will analyze requests and highlight potential cache deception issues.
- Vulnerability indicators and relevant metadata will be shown within the custom editor tab.

