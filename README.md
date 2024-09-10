# OneDrive Removal Script

A PowerShell script to completely remove OneDrive from Windows, including all associated files, folders, registry entries, and scheduled tasks.

## Prerequisites

- This script requires **administrator privileges** to run properly.
- Ensure **PowerShell 5.1** or higher is installed on your system.

## Usage

1. **Run PowerShell as Administrator**:
   - Press `Win + X` and choose `Windows PowerShell (Admin)`.

2. **Execute the following commands**:
   ```{powershell}
   Set-ExecutionPolicy Bypass -Scope Process -Force
   iex (iwr 'https://raw.githubusercontent.com/itsNileshHere/Onedrive-Removal/main/onedriveRemovalScript.ps1' -UseBasicParsing)
   ```

## Important Details

**The script will**:

* Terminate OneDrive process.
* Uninstall OneDrive from system.
* Copy files from OneDrive to user profile folder.
* Remove OneDrive leftovers.
* Revert user folders back to their default locations.

## Credits
- [winutil](https://github.com/ChrisTitusTech/winutil)
- [Windows 11 Forum](https://www.elevenforum.com/t/how-to-completely-remove-onedrive.12084/)
