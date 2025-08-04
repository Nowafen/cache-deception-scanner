# Cache Deception Scanner

A Burp Suite extension for detecting cache deception vulnerabilities in web applications.

## Overview
The **Cache Deception Scanner** is a Burp Suite extension designed to help security researchers and penetration testers identify cache deception vulnerabilities in web applications. This extension provides a custom request editor tab to visualize and analyze potential issues.

## Features
- Custom request editor tab for analyzing HTTP requests.
- Automated scanning for cache deception vulnerabilities.
- User-friendly interface with detailed vulnerability reporting.

## Prerequisites
- [Burp Suite](https://portswigger.net/burp) (Professional or Community Edition)
- Java Development Kit (JDK) 11 or higher
- Gradle (for building from source)

## Installation

### Option 1: Download Pre-built JAR (Recommended)
1. Go to the [Releases](https://github.com/Nowafen/cache-deception-scanner/releases) section of this repository.
2. Download the latest `wcd.jar` file.
3. Open Burp Suite, go to the **Extensions** tab, and click **Add**.
4. Select **Java** as the extension type, then browse and select the downloaded `wcd.jar` file.
5. Click **Next** to load the extension.

### Option 2: Build from Source
If you want to build the extension yourself or modify the source code:
1. Clone the repository:
   ```bash
   git clone https://github.com/Nowafen/cache-deception-scanner.git

2. Build the project using Gradle:
```
gradle build
```
The compiled wcd.jar file will be located in the build/libs/ directory.
Load the wcd.jar file in Burp Suite as described in Option 1.

##### Usage

After loading the extension, a new tab called Cache Deception Scanner will appear in Burp Suite's request editor.
Send HTTP requests to the extension for analysis.
The extension will highlight potential cache deception vulnerabilities and provide details in the custom tab.
