#!/usr/bin/env python3
"""
Mailinator Email Fetcher - General Purpose Tool
A CLI tool for fetching emails and OTP codes from Mailinator inboxes.

Usage:
    python mailinator-fetcher.py --inbox inboxname
    python mailinator-fetcher.py --inbox inboxname --wait-for-new
    python mailinator-fetcher.py --inbox inboxname --list-emails
"""

import argparse
import json
import logging
import os
import re
import sys
import time
import warnings
import websocket
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

# Suppress warnings before importing requests
warnings.filterwarnings("ignore")
os.environ['PYTHONWARNINGS'] = 'ignore'

import requests

# Also suppress the specific warning at the module level
import urllib3
urllib3.disable_warnings()

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Suppress requests warnings
logging.getLogger("requests").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

class MailinatorFetcher:
    """
    General-purpose Mailinator email fetcher with intelligent OTP detection.
    """
    
    def __init__(self, email_name: str):
        """
        Initialize the email fetcher.
        
        Args:
            email_name: The email name part (before @mailinator.com)
        """
        self.email_name = email_name
        self.email_address = f"{email_name}@mailinator.com"
        self.session = requests.Session()
        self.websocket = None
        self.initial_email_ids = set()
        self.script_start_time = datetime.now(timezone.utc)
        
        logger.info(f"🚀 Initialized fetcher for {self.email_address}")
    
    def get_session_cookies(self) -> bool:
        """Get session cookies by visiting the Mailinator inbox page."""
        try:
            logger.info(f"🍪 Getting session cookies for {self.email_name}")
            
            url = f"https://www.mailinator.com/v4/public/inboxes.jsp?to={self.email_name}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                jsessionid = self.session.cookies.get('JSESSIONID')
                if jsessionid:
                    logger.info(f"✅ Successfully obtained JSESSIONID: {jsessionid[:20]}...")
                    return True
                else:
                    logger.error("❌ No JSESSIONID cookie found")
                    return False
            else:
                logger.error(f"❌ Failed to get cookies: HTTP {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"❌ Error getting session cookies: {e}")
            return False
    
    def connect_websocket(self) -> bool:
        """Connect to Mailinator WebSocket and subscribe to email notifications."""
        try:
            logger.info("🔌 Connecting to Mailinator WebSocket...")
            
            if not self.get_session_cookies():
                return False
            
            # Get JSESSIONID cookie (exactly like working version)
            cookie_string = f"JSESSIONID={self.session.cookies.get('JSESSIONID')}"
            
            # Connect to WebSocket (exactly like working version)
            ws_url = "wss://www.mailinator.com/ws/fetchpublic"
            self.websocket = websocket.create_connection(
                ws_url,
                cookie=cookie_string
            )
            
            logger.info("✅ WebSocket connected successfully")
            
            # Send subscription command (exactly like working version)
            subscription = f'{{"cmd":"sub","channel":"{self.email_name}"}}'
            self.websocket.send(subscription)
            logger.info(f"📡 Sent subscription for channel: {self.email_name}")
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Error connecting to WebSocket: {e}")
            return False
    
    def get_initial_emails(self) -> List[Dict[str, Any]]:
        """Get initial emails to establish baseline."""
        try:
            logger.info("📧 Getting initial emails...")
            
            if not self.websocket:
                logger.error("❌ WebSocket not connected")
                return []
            
            initial_emails = []
            
            # Wait for initial_msgs response (exactly like working version)
            while True:
                message = self.websocket.recv()
                data = json.loads(message)
                
                logger.info(f"📨 Received message: {data.get('channel', 'unknown')}")
                
                if data.get('channel') == 'initial_msgs':
                    msgs = data.get('msgs', [])
                    logger.info(f"📊 Found {len(msgs)} initial emails")
                    
                    for msg in msgs:
                        email_id = msg.get('id')
                        if email_id:
                            self.initial_email_ids.add(email_id)
                            initial_emails.append(msg)
                    
                    logger.info(f"📊 Initial emails processed: {len(initial_emails)}")
                    break
                elif data.get('channel') == 'ping':
                    logger.debug("📡 Received ping")
                    continue
                else:
                    logger.debug(f"📨 Other message: {data.get('channel')}")
                    continue
            
            return initial_emails
            
        except Exception as e:
            logger.error(f"❌ Error getting initial emails: {e}")
            return []
    
    def get_email_content(self, email_id: str) -> Optional[Dict[str, Any]]:
        """Fetch full email content via HTTP API."""
        try:
            logger.info(f"📥 Fetching email content for ID: {email_id}")
            
            url = f"https://www.mailinator.com/fetch_public?msgid={email_id}"
            response = self.session.get(url, timeout=10)
            
            if response.status_code == 200:
                email_data = response.json()
                logger.info("✅ Successfully fetched email content")
                return email_data
            else:
                logger.error(f"❌ Failed to fetch email content: HTTP {response.status_code}")
                return None
                
        except Exception as e:
            logger.error(f"❌ Error fetching email content: {e}")
            return None
    
    def extract_otp_codes(self, email_content: Dict[str, Any]) -> List[str]:
        """Extract OTP codes from email content using intelligent pattern matching."""
        try:
            codes = []
            parts = email_content.get('parts', [])
            
            logger.info(f"🔍 Extracting OTP codes from {len(parts)} email parts")
            
            for part in parts:
                body = part.get('body', '')
                content_type = part.get('headers', {}).get('content-type', '')
                
                logger.debug(f"📄 Processing part with content-type: {content_type}")
                
                potential_codes = self._find_potential_otp_codes(body)
                
                for code_info in potential_codes:
                    code = code_info['code']
                    context = code_info['context']
                    confidence = code_info['confidence']
                    
                    logger.info(f"🔍 Found potential code: {code} (confidence: {confidence:.2f})")
                    logger.debug(f"📝 Context: {context}")
                    
                    if confidence >= 0.7:
                        codes.append(code)
                        logger.info(f"🔑 Accepted OTP code: {code}")
                    else:
                        logger.info(f"❌ Rejected low-confidence code: {code}")
            
            unique_codes = list(dict.fromkeys(codes))
            logger.info(f"✅ Extracted {len(unique_codes)} unique OTP codes: {unique_codes}")
            
            return unique_codes
            
        except Exception as e:
            logger.error(f"❌ Error extracting OTP codes: {e}")
            return []
    
    def _find_potential_otp_codes(self, text: str) -> List[Dict[str, Any]]:
        """Find potential OTP codes with confidence scoring."""
        potential_codes = []
        
        clean_text = re.sub(r'<[^>]+>', ' ', text)
        clean_text = re.sub(r'\s+', ' ', clean_text)
        
        number_pattern = r'\b\d{4,8}\b'
        matches = re.finditer(number_pattern, clean_text)
        
        for match in matches:
            code = match.group()
            start_pos = match.start()
            end_pos = match.end()
            
            context_start = max(0, start_pos - 50)
            context_end = min(len(clean_text), end_pos + 50)
            context = clean_text[context_start:context_end].strip()
            
            confidence = self._calculate_otp_confidence(code, context, clean_text)
            
            potential_codes.append({
                'code': code,
                'context': context,
                'confidence': confidence,
                'position': start_pos
            })
        
        potential_codes.sort(key=lambda x: x['confidence'], reverse=True)
        return potential_codes
    
    def _calculate_otp_confidence(self, code: str, context: str, full_text: str) -> float:
        """Calculate confidence score for a potential OTP code."""
        confidence = 0.0
        
        length_scores = {4: 0.8, 5: 0.9, 6: 1.0, 7: 0.7, 8: 0.6}
        confidence += length_scores.get(len(code), 0.3)
        
        positive_patterns = [
            (r'\b(?:code|otp|verification|pin|token|password|passcode)\b', 0.3),
            (r'\b(?:your|the|enter|use|input|type)\b', 0.2),
            (r'\b(?:is|are|will be|becomes)\b', 0.1),
            (r'[:\-]\s*' + re.escape(code), 0.4),
            (re.escape(code) + r'\s*[:\-]', 0.3),
            (r'\b(?:please|kindly|enter|input)\b.*?' + re.escape(code), 0.3),
            (re.escape(code) + r'\s*[.!?]', 0.2),
            (r'\b(?:temporary|one.?time|single.?use)\b', 0.2),
            (r'\b(?:expires?|valid|expiry)\b', 0.1),
        ]
        
        for pattern, score in positive_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                confidence += score
        
        negative_patterns = [
            (r'\b(?:date|time|year|month|day)\b', -0.4),
            (r'\b(?:phone|mobile|tel|call|from|sender)\b', -0.5),
            (r'\b(?:address|street|zip|postal)\b', -0.3),
            (r'\b(?:account|id|number|ref|reference)\b', -0.2),
            (r'\b(?:version|build|release)\b', -0.2),
            (r'\b(?:price|cost|amount|total)\b', -0.2),
            (r'\b(?:age|birth|born)\b', -0.2),
            (r'\b(?:serial|model|part)\b', -0.2),
            (r'\b(?:ip|url|link|http)\b', -0.2),
            (r'\b(?:order|invoice|receipt)\b', -0.2),
        ]
        
        for pattern, penalty in negative_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                confidence += penalty
        
        false_positive_patterns = [
            r'\d{4}-\d{2}-\d{2}',
            r'\d{2}/\d{2}/\d{4}',
            r'\d{2}:\d{2}(?::\d{2})?',
            r'\d{3}-\d{3}-\d{4}',
            r'\(\d{3}\)\s*\d{3}-\d{4}',
            r'\d{4}\s+\d{4}',
            r'\b\d{4}\s+\d{4}\s+\d{4}\s+\d{4}\b',
            r'\b\d{5}-\d{4}\b',
            r'\b\d{2,4}[A-Z]{2,4}\d{2,4}\b',
            r'\b\d{5,6}\b',
        ]
        
        for pattern in false_positive_patterns:
            if re.search(pattern, context):
                confidence -= 0.5
        
        code_occurrences = len(re.findall(re.escape(code), full_text))
        if code_occurrences > 2:
            confidence -= 0.3
        
        if len(set(code)) == 1:
            confidence -= 0.4
        elif code in ['1234', '12345', '123456', '0000', '00000', '000000']:
            confidence -= 0.3
        
        common_non_otp = [
            '2024', '2023', '2025',
            '1000', '2000', '3000',
            '9999', '8888', '7777',
        ]
        if code in common_non_otp:
            confidence -= 0.3
        
        phone_context_patterns = [
            r'from\s*:?\s*' + re.escape(code),
            r'sender\s*:?\s*' + re.escape(code),
            r'call\s*:?\s*' + re.escape(code),
            r'phone\s*:?\s*' + re.escape(code),
        ]
        
        for pattern in phone_context_patterns:
            if re.search(pattern, context, re.IGNORECASE):
                confidence -= 0.6
                break
        
        if len(code) >= 6:
            confidence -= 0.2
        
        confidence = max(0.0, min(1.0, confidence))
        return confidence
    
    def list_emails(self) -> List[Dict[str, Any]]:
        """List all emails in the inbox."""
        try:
            if not self.connect_websocket():
                return []
            
            emails = self.get_initial_emails()
            
            # Don't close WebSocket here - let the caller decide
            return emails
            
        except Exception as e:
            logger.error(f"❌ Error listing emails: {e}")
            return []
    
    def wait_for_new_email(self, timeout: int = 300) -> Optional[Dict[str, Any]]:
        """Wait for a new email notification."""
        try:
            logger.info(f"⏳ Waiting for new email (timeout: {timeout}s)...")
            logger.info(f"📧 Send an email to {self.email_address} now!")
            
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                message = self.websocket.recv()
                data = json.loads(message)
                
                logger.info(f"📨 Received message: {data.get('channel', 'unknown')}")
                
                if data.get('channel') == 'msg':
                    email_id = data.get('id')
                    logger.info(f"📧 Received email notification: {email_id}")
                    
                    if email_id and email_id not in self.initial_email_ids:
                        logger.info(f"🎉 New email detected: {email_id}")
                        
                        email_time = data.get('time', 0)
                        seconds_ago = data.get('seconds_ago', 0)
                        
                        if email_time == 0 and seconds_ago > 0:
                            current_time = time.time()
                            email_time = (current_time - seconds_ago) * 1000
                        
                        if email_time > 0:
                            email_datetime = datetime.fromtimestamp(email_time / 1000, tz=timezone.utc)
                        else:
                            email_datetime = datetime.now(timezone.utc)
                        
                        if email_datetime > self.script_start_time:
                            logger.info(f"✅ Email received after script start: {email_datetime}")
                            
                            new_email = {
                                'id': email_id,
                                'from': data.get('from'),
                                'fromfull': data.get('fromfull'),
                                'subject': data.get('subject'),
                                'time': email_time,
                                'datetime': email_datetime,
                                'seconds_ago': seconds_ago
                            }
                            
                            return new_email
                        else:
                            logger.info(f"⏰ Email was received before script start, ignoring: {email_datetime}")
                            continue
                    else:
                        logger.info(f"📧 Email already in initial set, ignoring: {email_id}")
                        continue
                
                elif data.get('channel') == 'ping':
                    logger.debug("📡 Received ping")
                    continue
                
                else:
                    logger.debug(f"📨 Other message: {data.get('channel')}")
                    continue
            
            logger.warning(f"⏰ Timeout reached ({timeout}s), no new email received")
            return None
            
        except Exception as e:
            logger.error(f"❌ Error waiting for new email: {e}")
            return None
    
    def get_otp_code(self, timeout: int = 300) -> Optional[str]:
        """Get an OTP code from a new email."""
        try:
            logger.info("🚀 Starting OTP code extraction...")
            
            if not self.connect_websocket():
                logger.error("❌ Failed to connect to WebSocket")
                return None
            
            initial_emails = self.get_initial_emails()
            logger.info(f"📊 Baseline established with {len(initial_emails)} existing emails")
            
            new_email = self.wait_for_new_email(timeout)
            if not new_email:
                logger.warning("⏰ No new email received within timeout")
                return None
            
            logger.info(f"📧 New email received: {new_email['subject']} from {new_email['from']}")
            
            email_content = self.get_email_content(new_email['id'])
            if not email_content:
                logger.error("❌ Failed to fetch email content")
                return None
            
            codes = self.extract_otp_codes(email_content)
            if not codes:
                logger.warning("⚠️ No OTP codes found in email")
                return None
            
            otp_code = codes[0]
            logger.info(f"🎉 Successfully extracted OTP code: {otp_code}")
            
            return otp_code
            
        except Exception as e:
            logger.error(f"❌ Error in get_otp_code: {e}")
            return None
        
        finally:
            if self.websocket:
                try:
                    self.websocket.close()
                    logger.info("🔌 WebSocket connection closed")
                except:
                    pass

def display_email_list(emails: List[Dict[str, Any]]) -> None:
    """Display list of emails in a user-friendly format."""
    if not emails:
        print("📭 No emails found in inbox")
        return
    
    print(f"\n📧 Found {len(emails)} emails in {emails[0].get('to', 'inbox')}@mailinator.com:")
    print("=" * 80)
    
    for i, email in enumerate(emails, 1):
        subject = email.get('subject', 'No Subject')
        sender = email.get('from', 'Unknown Sender')
        seconds_ago = email.get('seconds_ago', 0)
        
        if seconds_ago < 60:
            time_str = f"{seconds_ago}s ago"
        elif seconds_ago < 3600:
            time_str = f"{seconds_ago // 60}m ago"
        else:
            time_str = f"{seconds_ago // 3600}h ago"
        
        print(f"{i:2d}. {subject}")
        print(f"    From: {sender}")
        print(f"    Time: {time_str}")
        print()

def get_user_choice(max_choice: int) -> int:
    """Get user's email choice."""
    while True:
        try:
            choice = int(input(f"Enter email number (1-{max_choice}): "))
            if 1 <= choice <= max_choice:
                return choice - 1  # Convert to 0-based index
            else:
                print(f"Please enter a number between 1 and {max_choice}")
        except ValueError:
            print("Please enter a valid number")

def clean_html_content(html_content: str) -> str:
    """Clean HTML content for better display."""
    # Remove HTML tags
    clean = re.sub(r'<[^>]+>', ' ', html_content)
    
    # Decode HTML entities
    clean = clean.replace('&nbsp;', ' ')
    clean = clean.replace('&amp;', '&')
    clean = clean.replace('&lt;', '<')
    clean = clean.replace('&gt;', '>')
    clean = clean.replace('&quot;', '"')
    clean = clean.replace('&#8202;', '')  # Zero-width space
    clean = clean.replace('&zwnj;', '')   # Zero-width non-joiner
    
    # Clean up whitespace
    clean = re.sub(r'\s+', ' ', clean)
    clean = clean.strip()
    
    # Limit length for very long content
    if len(clean) > 2000:
        clean = clean[:2000] + "... (content truncated)"
    
    return clean

def display_email_content(email_content: Dict[str, Any], otp_codes: List[str] = None) -> None:
    """Display email content in a user-friendly format."""
    print("\n" + "=" * 80)
    print("📧 EMAIL CONTENT")
    print("=" * 80)
    
    parts = email_content.get('parts', [])
    data = email_content.get('data', {})
    
    # Check if we have parts or data
    if not parts and not data:
        print("❌ No email content found")
        return
    
    # Handle different email content structures
    if parts:
        for i, part in enumerate(parts, 1):
            content_type = part.get('headers', {}).get('content-type', '')
            body = part.get('body', '')
            
            print(f"\n📄 Part {i} ({content_type}):")
            print("-" * 40)
            
            if body:
                clean_body = clean_html_content(body)
                print(clean_body)
            else:
                print("(Empty content)")
    
    elif data:
        # Handle data structure
        if 'parts' in data:
            for i, part in enumerate(data['parts'], 1):
                content_type = part.get('headers', {}).get('content-type', '')
                body = part.get('body', '')
                
                print(f"\n📄 Part {i} ({content_type}):")
                print("-" * 40)
                
                if body:
                    clean_body = clean_html_content(body)
                    print(clean_body)
                else:
                    print("(Empty content)")
        else:
            print("❌ No readable content found in email data")
    
    # Show OTP codes if provided
    if otp_codes:
        print(f"\n🔑 OTP CODES FOUND: {', '.join(otp_codes)}")

def main():
    """Main CLI function."""
    parser = argparse.ArgumentParser(
        description="Mailinator Email Fetcher - Fetch emails and OTP codes from Mailinator inboxes",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python mailinator-fetcher.py --inbox myinbox
  python mailinator-fetcher.py --inbox myinbox --wait-for-new
  python mailinator-fetcher.py --inbox myinbox --list-emails
  python mailinator-fetcher.py --inbox myinbox --fetch-otp
  python mailinator-fetcher.py --inbox myinbox --wait-for-new --fetch-otp
        """
    )
    
    parser.add_argument(
        '--inbox', 
        required=True, 
        help='Mailinator inbox name (without @mailinator.com)'
    )
    
    parser.add_argument(
        '--wait-for-new', 
        action='store_true', 
        help='Wait for a new email and extract OTP code'
    )
    
    parser.add_argument(
        '--list-emails', 
        action='store_true', 
        help='List all emails in the inbox'
    )
    
    parser.add_argument(
        '--fetch-otp', 
        action='store_true', 
        help='Extract OTP codes from emails (use with --wait-for-new or when viewing emails)'
    )
    
    parser.add_argument(
        '--timeout', 
        type=int, 
        default=600, 
        help='Timeout in seconds for waiting for new emails (default: 600)'
    )
    
    args = parser.parse_args()
    
    print("🚀 Mailinator Email Fetcher")
    print("=" * 50)
    print(f"📧 Inbox: {args.inbox}@mailinator.com")
    print()
    
    fetcher = MailinatorFetcher(args.inbox)
    
    if args.list_emails:
        # List emails mode
        emails = fetcher.list_emails()
        
        if not emails:
            print("📭 Inbox is empty!")
            print("💡 Send an email to the inbox and try again")
            return
        
        display_email_list(emails)
        
        # Ask user to select an email
        choice = get_user_choice(len(emails))
        selected_email = emails[choice]
        
        print(f"\n📥 Fetching content for: {selected_email.get('subject', 'No Subject')}")
        
        # Fetch email content
        email_content = fetcher.get_email_content(selected_email['id'])
        if email_content:
            if args.fetch_otp:
                otp_codes = fetcher.extract_otp_codes(email_content)
                display_email_content(email_content, otp_codes)
            else:
                display_email_content(email_content)
        else:
            print("❌ Failed to fetch email content")
        
        # Close WebSocket connection
        if fetcher.websocket:
            fetcher.websocket.close()
    
    elif args.wait_for_new:
        # Wait for new email mode
        if args.fetch_otp:
            print("⏳ Waiting for new email...")
            print("💡 Send an email with an OTP code to the inbox now!")
            
            start_time = time.time()
            otp_code = fetcher.get_otp_code(timeout=args.timeout)
            end_time = time.time()
            
            if otp_code:
                print(f"\n🎉 SUCCESS!")
                print(f"🔑 OTP Code: {otp_code}")
                print(f"⏱️  Time taken: {end_time - start_time:.1f} seconds")
            else:
                print(f"\n❌ FAILED!")
                print(f"⏱️  Time taken: {end_time - start_time:.1f} seconds")
                print("💡 Try sending an email with clear OTP context")
        else:
            print("⏳ Waiting for new email...")
            print("💡 Send an email to the inbox now!")
            
            start_time = time.time()
            new_email = fetcher.wait_for_new_email(timeout=args.timeout)
            end_time = time.time()
            
            if new_email:
                print(f"\n🎉 NEW EMAIL RECEIVED!")
                print(f"📧 From: {new_email.get('from', 'Unknown')}")
                print(f"📝 Subject: {new_email.get('subject', 'No Subject')}")
                print(f"⏱️  Time taken: {end_time - start_time:.1f} seconds")
                
                # Fetch and display email content
                email_content = fetcher.get_email_content(new_email['id'])
                if email_content:
                    display_email_content(email_content)
            else:
                print(f"\n❌ TIMEOUT!")
                print(f"⏱️  Time taken: {end_time - start_time:.1f} seconds")
                print("💡 No new email received within the timeout period")
    
    else:
        # Default mode - list emails or wait for new
        if args.fetch_otp:
            # If --fetch-otp is specified, directly wait for new email with OTP extraction
            print("⏳ Waiting for new email with OTP code...")
            print("💡 Send an email with an OTP code to the inbox now!")
            
            start_time = time.time()
            otp_code = fetcher.get_otp_code(timeout=args.timeout)
            end_time = time.time()
            
            if otp_code:
                print(f"\n🎉 SUCCESS!")
                print(f"🔑 OTP Code: {otp_code}")
                print(f"⏱️  Time taken: {end_time - start_time:.1f} seconds")
            else:
                print(f"\n❌ FAILED!")
                print(f"⏱️  Time taken: {end_time - start_time:.1f} seconds")
                print("💡 Try sending an email with clear OTP context")
        else:
            # Normal mode - list emails and ask user what to do
            emails = fetcher.list_emails()
            
            if not emails:
                print("📭 Inbox is empty!")
                print("💡 Send an email to the inbox and try again")
                return
            
            # Ask user what they want to do first
            print("\nWhat would you like to do?")
            print("1. View an existing email")
            print("2. Wait for a new email")
            
            while True:
                try:
                    choice = int(input("Enter choice (1 or 2): "))
                    if choice in [1, 2]:
                        break
                    else:
                        print("Please enter 1 or 2")
                except ValueError:
                    print("Please enter a valid number")
            
            # Now show the emails
            display_email_list(emails)
            
            if choice == 1:
                # View existing email
                email_choice = get_user_choice(len(emails))
                selected_email = emails[email_choice]
                
                print(f"\n📥 Fetching content for: {selected_email.get('subject', 'No Subject')}")
                
                email_content = fetcher.get_email_content(selected_email['id'])
                if email_content:
                    # Show full email content
                    if args.fetch_otp:
                        otp_codes = fetcher.extract_otp_codes(email_content)
                        display_email_content(email_content, otp_codes)
                    else:
                        display_email_content(email_content)
                else:
                    print("❌ Failed to fetch email content")
                
                # Close WebSocket connection
                if fetcher.websocket:
                    fetcher.websocket.close()
            
            else:
                # Wait for new email
                if args.fetch_otp:
                    print("\n⏳ Waiting for new email...")
                    print("💡 Send an email with an OTP code to the inbox now!")
                    
                    start_time = time.time()
                    otp_code = fetcher.get_otp_code(timeout=args.timeout)
                    end_time = time.time()
                    
                    if otp_code:
                        print(f"\n🎉 SUCCESS!")
                        print(f"🔑 OTP Code: {otp_code}")
                        print(f"⏱️  Time taken: {end_time - start_time:.1f} seconds")
                    else:
                        print(f"\n❌ FAILED!")
                        print(f"⏱️  Time taken: {end_time - start_time:.1f} seconds")
                        print("💡 Try sending an email with clear OTP context")
                else:
                    print("\n⏳ Waiting for new email...")
                    print("💡 Send an email to the inbox now!")
                    
                    start_time = time.time()
                    new_email = fetcher.wait_for_new_email(timeout=args.timeout)
                    end_time = time.time()
                    
                    if new_email:
                        print(f"\n🎉 NEW EMAIL RECEIVED!")
                        print(f"📧 From: {new_email.get('from', 'Unknown')}")
                        print(f"📝 Subject: {new_email.get('subject', 'No Subject')}")
                        print(f"⏱️  Time taken: {end_time - start_time:.1f} seconds")
                        
                        # Fetch and display email content
                        email_content = fetcher.get_email_content(new_email['id'])
                        if email_content:
                            display_email_content(email_content)
                    else:
                        print(f"\n❌ TIMEOUT!")
                        print(f"⏱️  Time taken: {end_time - start_time:.1f} seconds")
                        print("💡 No new email received within the timeout period")

if __name__ == "__main__":
    main()
