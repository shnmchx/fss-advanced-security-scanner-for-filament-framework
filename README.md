# Filament Scan

> Advanced Security Scanner for Laravel Filament Applications  
> Detects misconfigurations, exposures, and vulnerabilities during development

[![Python Version](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/yourusername/filament-scan/pulls)

---

## 📖 Overview

**Filament Scan** is a specialized security assessment tool built for Laravel applications that use the **Filament** admin panel framework. It helps developers identify common security misconfigurations and vulnerabilities during the **development phase**, before the application is deployed to production.

Filament is powerful and flexible, but its complexity can introduce security risks. Debug tools left enabled, exposed routes, default credentials, and misconfigured middleware are common oversights. Filament Scan automates the detection of these issues, saving time and reducing risk.

---

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| **Filament Detection** | Automatically identifies if the target uses Filament |
| **Debug Mode Exposure** | Checks for accessible debugbar, Telescope, Ignition, and Horizon |
| **Resource Exposure** | Detects Filament resources accessible without authentication |
| **Default Credentials** | Tests against common default login credentials (admin@example.com/password, etc.) |
| **Configuration Leakage** | Scans for exposed `.env`, `config.js`, and `manifest.json` files |
| **File Upload Security** | Tests for unrestricted PHP file uploads via Filament media upload |
| **Livewire Endpoint Exposure** | Identifies exposed Livewire message and update endpoints |
| **Middleware Bypass** | Checks if the admin panel is accessible without authentication |
| **Environment Dump** | Detects exposed `/debug`, `/phpinfo`, `/env`, and similar endpoints |
| **Brute Force Detection** | Attempts login with weak and commonly used passwords |

---

## 🚀 Installation

### Prerequisites

- Python 3.6 or higher
- `requests` library

### Clone the Repository

```bash
git clone https://github.com/yourusername/filament-scan.git
cd filament-scan
