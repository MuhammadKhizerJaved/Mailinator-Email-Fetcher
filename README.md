# Mailinator Email Fetcher

A powerful CLI tool for fetching emails from Mailinator inboxes without requiring an API key. Perfect for testing, automation, and development workflows.

## ✨ Features

- **📧 Full Email Access** - View complete email content from any Mailinator inbox
- **🔍 Interactive Mode** - User-friendly interface for selecting and viewing emails
- **⚡ Real-time Monitoring** - Wait for new emails and get instant notifications
- **🧠 Intelligent OTP Detection** - Optional advanced pattern recognition for OTP codes
- **📱 Phone Number Filtering** - Automatically distinguishes OTP codes from phone numbers
- **🎯 Confidence Scoring** - Assigns confidence scores to potential codes for accurate detection
- **🛡️ Robust Error Handling** - Comprehensive error handling and logging
- **🚀 No API Key Required** - Works directly with Mailinator's public interface

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Direct OTP extraction (recommended for automation)
python mailinator-fetcher.py --inbox myinbox --fetch-otp

# Interactive email viewing
python mailinator-fetcher.py --inbox myinbox
```

## 📦 Installation

1. Clone or download this repository
2. Install required dependencies:
```bash
pip install -r requirements.txt
```

## 🚀 Usage

### Basic Usage

```bash
# Interactive mode - view existing emails or wait for new ones
python mailinator-fetcher.py --inbox myinbox

# Direct OTP extraction - wait for new email with OTP code
python mailinator-fetcher.py --inbox myinbox --fetch-otp

# Wait for a new email (general mode)
python mailinator-fetcher.py --inbox myinbox --wait-for-new

# List all emails in an inbox
python mailinator-fetcher.py --inbox myinbox --list-emails
```

### Command Line Options

- `--inbox INBOX_NAME` - Mailinator inbox name (required)
- `--fetch-otp` - Extract OTP codes from emails (use with --wait-for-new or when viewing emails)
- `--wait-for-new` - Wait for a new email
- `--list-emails` - List all emails in the inbox
- `--timeout SECONDS` - Timeout for waiting for new emails (default: 600)

### Examples

```bash
# Interactive mode - will show emails and let you choose
python mailinator-fetcher.py --inbox testinbox

# Direct OTP extraction - no user interaction needed
python mailinator-fetcher.py --inbox testinbox --fetch-otp

# Wait for new email with OTP extraction
python mailinator-fetcher.py --inbox testinbox --wait-for-new --fetch-otp

# Wait for new email (general mode)
python mailinator-fetcher.py --inbox testinbox --wait-for-new

# List all emails with OTP extraction
python mailinator-fetcher.py --inbox testinbox --list-emails --fetch-otp

# Custom timeout
python mailinator-fetcher.py --inbox testinbox --fetch-otp --timeout 300
```

## 🧠 Intelligent OTP Detection

### ✅ What It Detects (High Confidence)
- **OTP Codes**: 4-8 digit numbers with OTP context
- **Verification Codes**: Numbers near words like "code", "OTP", "verification"
- **Access Codes**: Numbers in security-related contexts
- **PIN Codes**: Short numeric codes for authentication

### ❌ What It Filters Out (Low Confidence)
- **Phone Numbers**: 5-6 digit numbers in phone context
- **Dates**: 2024, 2025, etc.
- **Times**: 14:30, 15:45, etc.
- **Account IDs**: Reference numbers, order numbers
- **Addresses**: ZIP codes, postal codes

### 🎯 Confidence Scoring System
- **0.7+ confidence**: ✅ Accepted as OTP
- **<0.7 confidence**: ❌ Rejected as false positive

## 📊 Example Output

### Interactive Mode (Default)
```
🚀 Mailinator Email Fetcher
==================================================
📧 Inbox: testinbox@mailinator.com

What would you like to do?
1. View an existing email
2. Wait for a new email
Enter choice (1 or 2): 1

📧 Found 3 emails in testinbox@mailinator.com:
================================================================================
 1. SMS Forwarding
    From: Call.com Support
    Time: 2m ago

 2. Verification Code
    From: noreply@example.com
    Time: 5m ago

 3. Order Confirmation
    From: orders@shop.com
    Time: 1h ago

Enter email number (1-3): 2

📥 Fetching content for: Verification Code

================================================================================
📧 EMAIL CONTENT
================================================================================

📄 Part 1 (text/plain):
----------------------------------------
Your verification code is 123456
Please enter this code to verify your account.
```

### Direct OTP Extraction Mode
```
🚀 Mailinator Email Fetcher
==================================================
📧 Inbox: testinbox@mailinator.com

⏳ Waiting for new email with OTP code...
💡 Send an email with an OTP code to the inbox now!

🎉 SUCCESS!
🔑 OTP Code: 1610
⏱️  Time taken: 14.1 seconds
```

### Wait for New Email Mode (General)
```
🚀 Mailinator Email Fetcher
==================================================
📧 Inbox: testinbox@mailinator.com

⏳ Waiting for new email...
💡 Send an email to the inbox now!

🎉 NEW EMAIL RECEIVED!
📧 From: noreply@example.com
📝 Subject: Welcome to our service
⏱️  Time taken: 8.3 seconds
```

## 🔧 Advanced Usage

### Direct OTP Extraction (Recommended for Automation)
```bash
# No user interaction - directly waits for OTP
python mailinator-fetcher.py --inbox myinbox --fetch-otp

# With custom timeout
python mailinator-fetcher.py --inbox myinbox --fetch-otp --timeout 300
```

### Interactive Email Viewing
```bash
# View existing emails interactively
python mailinator-fetcher.py --inbox myinbox

# List emails and extract OTP from selected email
python mailinator-fetcher.py --inbox myinbox --list-emails --fetch-otp
```

### General Email Monitoring
```bash
# Wait for any new email (not just OTP)
python mailinator-fetcher.py --inbox myinbox --wait-for-new

# List all emails without interaction
python mailinator-fetcher.py --inbox myinbox --list-emails
```

## 📋 Requirements

- Python 3.7+
- requests
- websocket-client

## 🔍 How It Works

1. **🔌 WebSocket Connection** - Connects to Mailinator's WebSocket API
2. **🍪 Session Management** - Obtains and manages session cookies
3. **📧 Email Monitoring** - Listens for new email notifications or fetches existing emails
4. **📥 Content Fetching** - Retrieves full email content via HTTP API
5. **🧠 Intelligent Detection** - Uses advanced pattern recognition
6. **🎯 Confidence Scoring** - Assigns confidence scores to potential codes
7. **🔍 Context Analysis** - Analyzes surrounding text for context clues
8. **✅ Final Selection** - Returns the highest confidence OTP code

## 📝 Logging

The tool provides detailed logging for debugging:
```
2025-09-06 03:49:16,634 - INFO - 🔍 Found potential code: 0758 (confidence: 1.00)
2025-09-06 03:49:16,634 - INFO - 🔑 Accepted OTP code: 0758
2025-09-06 03:49:16,635 - INFO - ✅ Extracted 1 unique OTP codes: ['0758']
```

## 🛡️ Error Handling

Comprehensive error handling for:
- WebSocket connection failures
- HTTP request timeouts
- Email parsing errors
- Network connectivity issues
- Invalid email formats
- Empty inboxes

## 🎯 Use Cases

### 🔧 Development & Testing
- **Email Testing** - View and analyze emails sent to test inboxes
- **OTP Testing** - Extract OTP codes for authentication testing
- **Quality Assurance** - Test email-based systems and notifications
- **Development Workflows** - Integrate into CI/CD pipelines for email testing

### 🤖 Automation & Integration
- **Automation Scripts** - Build custom automation on top of this tool
- **CI/CD Integration** - Use `--fetch-otp` for automated testing
- **API Testing** - Verify email delivery in API tests
- **User Registration Testing** - Test email verification flows

### 📊 Analysis & Monitoring
- **Email Monitoring** - Monitor Mailinator inboxes for specific emails
- **Research and Analysis** - Analyze email patterns and content
- **Debugging** - Troubleshoot email delivery issues
- **Content Analysis** - Study email formats and structures

## 🔧 Customization & Extension

This tool is designed to be easily customizable and extensible:

### 🏗️ Building on Top
- **Use the `MailinatorFetcher` class** in your own projects
- **Import and extend** the functionality for custom workflows
- **Integrate with automation** - Use as a building block for larger automation systems

### 🧠 Customizing OTP Detection
- **Modify confidence scoring** - Adjust the pattern recognition algorithms
- **Add new patterns** - Extend the detection for specific OTP formats
- **Customize filtering** - Add domain-specific false positive patterns

### 🚀 Adding Features
- **Extend functionality** - Add new features for your specific needs
- **Modify for different use cases** - Adapt the tool for various email processing needs
- **Add new output formats** - JSON, CSV, or custom formats

---


**Note**: This tool is designed for legitimate testing and development purposes. Always respect the terms of service of the services you're testing with.
