# SKULL-NetRecon Installation Script
# Run this script to set up SKULL-NetRecon

Write-Host "=" -NoNewline
Write-Host "===============================================" -ForegroundColor Cyan
Write-Host "  SKULL-NetRecon Installation Script" -ForegroundColor Cyan
Write-Host "===============================================`n" -ForegroundColor Cyan

# Check Python installation
Write-Host "[*] Checking Python installation..." -ForegroundColor Yellow
try {
    $pythonVersion = python --version 2>&1
    if ($pythonVersion -match "Python (\d+)\.(\d+)") {
        $major = [int]$matches[1]
        $minor = [int]$matches[2]
        
        if ($major -ge 3 -and $minor -ge 8) {
            Write-Host "[+] Python $major.$minor found" -ForegroundColor Green
        } else {
            Write-Host "[!] Python 3.8 or higher is required. Found: $pythonVersion" -ForegroundColor Red
            exit 1
        }
    }
} catch {
    Write-Host "[!] Python not found. Please install Python 3.8 or higher." -ForegroundColor Red
    exit 1
}

# Create necessary directories
Write-Host "`n[*] Creating directories..." -ForegroundColor Yellow
$directories = @("logs", "reports")

foreach ($dir in $directories) {
    if (!(Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
        Write-Host "[+] Created: $dir" -ForegroundColor Green
    } else {
        Write-Host "[*] Directory exists: $dir" -ForegroundColor Cyan
    }
}

# Install Python dependencies
Write-Host "`n[*] Installing Python dependencies..." -ForegroundColor Yellow
Write-Host "[!] This may take a few minutes..." -ForegroundColor Yellow

try {
    python -m pip install --upgrade pip | Out-Null
    python -m pip install -r requirements.txt
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] Dependencies installed successfully" -ForegroundColor Green
    } else {
        Write-Host "[!] Some dependencies failed to install" -ForegroundColor Red
        Write-Host "[*] You may need to install them manually" -ForegroundColor Yellow
    }
} catch {
    Write-Host "[!] Failed to install dependencies: $_" -ForegroundColor Red
    exit 1
}

# Verify installation
Write-Host "`n[*] Verifying installation..." -ForegroundColor Yellow

$requiredModules = @(
    "scapy",
    "rich",
    "yaml",
    "jinja2",
    "requests",
    "netifaces"
)

$allInstalled = $true
foreach ($module in $requiredModules) {
    $result = python -c "import $module" 2>&1
    if ($LASTEXITCODE -eq 0) {
        Write-Host "[+] $module installed" -ForegroundColor Green
    } else {
        Write-Host "[!] $module not found" -ForegroundColor Red
        $allInstalled = $false
    }
}

# Final status
Write-Host "`n" -NoNewline
Write-Host "===============================================" -ForegroundColor Cyan

if ($allInstalled) {
    Write-Host "[+] Installation completed successfully!" -ForegroundColor Green
    Write-Host "`nYou can now run SKULL-NetRecon:" -ForegroundColor Yellow
    Write-Host "  python skull_netrecon.py --target <TARGET>" -ForegroundColor White
    Write-Host "`nFor help:" -ForegroundColor Yellow
    Write-Host "  python skull_netrecon.py --help" -ForegroundColor White
} else {
    Write-Host "[!] Installation completed with errors" -ForegroundColor Red
    Write-Host "Please install missing dependencies manually" -ForegroundColor Yellow
}

Write-Host "===============================================`n" -ForegroundColor Cyan

# Important notes
Write-Host "IMPORTANT NOTES:" -ForegroundColor Red
Write-Host "  - Some features require Administrator privileges" -ForegroundColor Yellow
Write-Host "  - Always obtain authorization before scanning" -ForegroundColor Yellow
Write-Host "  - Review LEGAL.md for legal information`n" -ForegroundColor Yellow
