# PowerShellThreatHunter_v2.0-Env
Powershell ThreatHunter v2.0 for Secure Environments

Author: 0xAllow


![PowerShell Version](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows-blue)
![License](https://img.shields.io/badge/License-GPLv3-blue)


PThreatHunter v2.0 is an advanced forensic script designed for security analysts, system administrators, and blue teamers to hunt for malware persistence techniques and indicators of compromise (IOCs) on Windows systems.

Its key feature is its full compatibility with **PowerShell's Constrained Language Mode (CLM)**, making it one of the few advanced threat hunting tools capable of running in highly secured and locked-down corporate environments.

---

## Designed for Hostile Environments: What is Constrained Language Mode?

In modern, security-conscious environments, PowerShell is often restricted by security policies like **AppLocker** or **Windows Defender Application Control (WDAC)**. When these policies are active, PowerShell runs in **Constrained Language Mode**.

**What does this mean?**
-   It drastically limits what PowerShell can do to prevent malicious script execution.
-   It blocks the creation of complex .NET objects.
-   It prevents method invocation on most types (e.g., you cannot use `$string.Split()` or `$item.PSObject.Properties`).
-   Many advanced cmdlets and variables are disabled.

This security measure renders most publicly available PowerShell security tools **completely useless**, as they rely on these advanced features.

**PThreatHunter was meticulously rewritten (v2.0) to overcome this challenge.** It uses only core, allowed cmdlets and operators to provide advanced forensic capabilities without violating CLM restrictions, allowing you to hunt for threats even on the most hardened systems.

---

## Key Features (v2.0)

PThreatHunter v2.0 combines robust data collection with intelligent analysis, providing a comprehensive overview of system persistence.

-   **CLM Compatible:** Fully functional in environments with AppLocker and other application control solutions.
-   **Threat Scoring System:** Findings are automatically assigned a "Threat Score" to help you prioritize the most critical alerts.
-   **Advanced Persistence Detection:**
    -   **WMI Persistence:** Uncovers "fileless" threats hiding in WMI event consumers and filters.
    -   **COM Hijacking:** Scans the registry for hijacked COM objects used to load malicious DLLs into trusted processes.
    -   **PowerShell Profiles:** Checks all user and system PowerShell profiles for malicious code.
-   **Standard Persistence Vectors:**
    -   **Registry Autoruns:** Scans all common `Run`, `RunOnce`, and `Winlogon` keys.
    -   **Services:** Enumerates all system services.
    -   **Scheduled Tasks:** Gathers all scheduled tasks and their actions.
-   **Event Log Analysis:**
    -   Scans **PowerShell script block logs (ID 4104)** for suspicious keywords and encoded commands.
    -   Scans **Process Creation logs (ID 4688)** for command-line evidence of threat actor activity.
-   **Automated File Hashing:** Intelligently extracts file paths from command lines and calculates their SHA256 hash.
-   **Smart Summary:** At the end of the scan, it provides a sorted list of the most suspicious findings, allowing for rapid triage.
-   **Comprehensive Export:** Saves all collected artifacts into detailed `JSON` and `CSV` files for deep analysis and record-keeping.

---

## Prerequisites

-   **Operating System:** Windows 10, Windows 11, Windows Server 2016 or newer.
-   **PowerShell Version:** 5.1 or higher.
-   **Permissions:** Must be run with **Administrator privileges** to perform a full system scan.

## How to Use

1.  **Download the Script**
    -   Download `PThreatHunter.ps1` to your machine.
    -   Place it in a non-protected folder, for example `C:\Tools\`.

2.  **Open PowerShell as Administrator**
    -   Click Start, type `PowerShell`.
    -   Right-click on "Windows PowerShell" and select "Run as administrator".

3.  **Navigate to the Script's Directory**
    ```powershell
    cd C:\Tools\
    ```

4.  **Set the Execution Policy (for the current session)**
    If you haven't run scripts before, you may need to bypass the execution policy.
    ```powershell
    Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
    ```

5.  **Run the Script**
    ```powershell
    .\PThreatHunter_v2.0.ps1
    ```
    The script will display its findings in the console and create a `PThreatHunter-Report` folder in your user profile with the detailed JSON/CSV reports.

## Understanding the Output

The script provides two main forms of output:
1.  **The Smart Summary:** A table displayed in the console at the end of the scan, sorted by `ThreatScore`. This is your starting point for investigation.
2.  **Exported Files (`.json`, `.csv`):** These files contain **all** the data collected, not just the suspicious items. Use these files to get more context on a finding from the summary, especially to find the `FileHash` to check on VirusTotal.

## ⚠️ Disclaimer

-   This is a forensic tool, not an antivirus. It is designed to find indicators of compromise, not to block or remove them.
-   This script is not a replacement for professional EDR/XDR solutions. Advanced threats may use techniques to evade this script.
-   False positives are possible. Always investigate findings before taking action.
-   Use this script at your own risk. The author is not responsible for any damage caused.

## License

This project is licensed under the GNU License.
