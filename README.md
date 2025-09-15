# CTFd Flag Format Checker

CTFd plugin that validates flag submissions against regex patterns.

<div align="center" style="display: flex; align-items: center; justify-content: center; gap: 10px;">
  <img src="images/admin.png" width="55%" alt="Admin Settings">
  <img src="images/chall.png" width="35%" alt="Challenge Validation">
</div>

## Installation

Copy to CTFd's plugins directory (`$CTFD_DIR/CTFd/plugins/`) and restart.

## Usage

Access `/admin/flag-format` to configure flag format validation:

1. Set regex pattern (e.g., `flag\{.*\}`)
2. Customize error message
3. Enable/disable validation
