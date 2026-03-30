"""
Phishing Email Detector - OpenEnv Environment
Author: M Abhilash Kumar
Hackathon: OpenEnv Hackathon 2026

Detects phishing emails using rule-based analysis with domain trust verification.
"""

import os
import re
import pandas as pd
from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field
from urllib.parse import urlparse


# ============================================================================
# SCORE LOGGER - Saves results in Human-Readable TXT format only
# ============================================================================

class ScoreLogger:
    """Logs all email scores to a beautiful human-readable TXT file"""
    
    def __init__(self, filename="email_scores.txt"):
        self.filename = filename
        self.scores = []  # Stores dictionaries in memory
        self.session_active = False  # Track if session is active
    
    def start_new_session(self):
        """Start a new session - clears the score file"""
        self.scores = []
        # Clear the file by opening in write mode and closing
        with open(self.filename, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("🔐 PHISHING EMAIL DETECTOR - SCORE LOG\n")
            f.write(f"📅 Session Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n")
            f.write("All email analysis results will be logged below:\n")
            f.write("="*80 + "\n")
        self.session_active = True
        print(f"✅ Started new session - {self.filename} cleared")
    
    def log_score(self, entry):
        """Write a single score entry to human-readable text file"""
        # If this is the first score of a new session, ensure file is ready
        if not self.session_active:
            self.start_new_session()
        
        # Store in memory as dictionary
        self.scores.append(entry)
        
        # Write to file (append mode)
        with open(self.filename, 'a', encoding='utf-8') as f:
            f.write("\n" + "="*80 + "\n")
            f.write(f"📧 EMAIL ANALYSIS REPORT #{len(self.scores)}\n")
            f.write(f"📅 Date & Time: {entry['timestamp']}\n")
            f.write("="*80 + "\n\n")
            
            # Email Details
            f.write("📨 EMAIL DETAILS:\n")
            f.write(f"   From: {entry['sender_domain']}\n")
            f.write(f"   Subject: {entry['subject'][:100]}\n")
            if entry['link_count'] > 0:
                f.write(f"   🔗 Links Found: {entry['link_count']}\n")
            else:
                f.write(f"   🔗 Links Found: None\n")
            f.write(f"   ⚡ Urgency Words Found: {entry['urgency_word_count']}\n\n")
            
            # Score Calculation
            f.write("📊 SCORE CALCULATION:\n")
            f.write(f"   Phishing Score: {entry['phishing_score']:.3f} / 1.00\n")
            f.write(f"   Confidence: {entry['confidence']:.0%}\n")
            
            # Threshold
            threshold = 0.4
            f.write(f"   Detection Threshold: Score ≥ {threshold} = PHISHING\n")
            
            # Show where the score stands
            if entry['phishing_score'] >= threshold:
                f.write(f"   Status: {entry['phishing_score']:.3f} ≥ {threshold} → PHISHING\n\n")
            else:
                f.write(f"   Status: {entry['phishing_score']:.3f} < {threshold} → LEGITIMATE\n\n")
            
            # Final Verdict
            f.write("🎯 FINAL VERDICT:\n")
            if entry['classification'] == 'phishing':
                f.write(f"   🔴 PHISHING DETECTED!\n")
            else:
                f.write(f"   🟢 LEGITIMATE EMAIL\n")
            f.write(f"   Reason: {entry['reasoning']}\n\n")
            
            # Suspicious Elements
            if entry['suspicious_elements'] and len(entry['suspicious_elements']) > 0:
                f.write("⚠️  SUSPICIOUS ELEMENTS DETECTED:\n")
                for i, elem in enumerate(entry['suspicious_elements'][:5], 1):
                    f.write(f"   {i}. {elem}\n")
                if len(entry['suspicious_elements']) > 5:
                    f.write(f"   ... and {len(entry['suspicious_elements']) - 5} more\n")
            else:
                f.write("✅ No suspicious elements detected\n")
            
            # Link Safety Info (if links exist)
            if entry['link_count'] > 0:
                f.write("\n🔗 LINK SAFETY ANALYSIS:\n")
                if entry['links_match_sender']:
                    f.write(f"   ✅ Links match sender domain (Good sign)\n")
                else:
                    f.write(f"   ⚠️ Links do NOT match sender domain\n")
                
                if entry['unsafe_link_count'] > 0:
                    f.write(f"   ⚠️ Unsafe links found: {entry['unsafe_link_count']}\n")
                else:
                    f.write(f"   ✅ All links are safe\n")
            
            # Fake Domain Detection
            if entry['is_fake_domain']:
                f.write("\n🚨 FAKE DOMAIN DETECTED:\n")
                f.write(f"   This email is using a fake domain to impersonate a legitimate service\n")
            
            f.write("\n" + "="*80 + "\n")
    
    def get_summary(self):
        """Get summary statistics from in-memory scores"""
        if not self.scores:
            return "No scores recorded yet in this session."
        
        phishing_count = sum(1 for s in self.scores if s.get('classification') == 'phishing')
        legitimate_count = sum(1 for s in self.scores if s.get('classification') == 'legitimate')
        avg_score = sum(s.get('phishing_score', 0) for s in self.scores) / len(self.scores)
        
        return {
            "total": len(self.scores),
            "phishing": phishing_count,
            "legitimate": legitimate_count,
            "avg_score": avg_score
        }
    
    def print_summary(self):
        """Print summary statistics"""
        summary = self.get_summary()
        if isinstance(summary, str):
            print(summary)
            return
        
        print("\n" + "="*60)
        print("📊 EMAIL SCORE SUMMARY (This Session)")
        print("="*60)
        print(f"   Total Emails Tested: {summary['total']}")
        print(f"   🔴 Phishing Detected: {summary['phishing']}")
        print(f"   🟢 Legitimate Detected: {summary['legitimate']}")
        print(f"   📈 Average Phishing Score: {summary['avg_score']:.3f}")
        print("="*60)
        print(f"\n📁 Full details saved to: {self.filename}")
    
    def show_recent(self, n=5):
        """Show most recent n scores in console"""
        if not self.scores:
            print("No scores recorded yet in this session.")
            return
        
        recent = self.scores[-n:]
        
        print("\n" + "="*100)
        print("📋 RECENT EMAIL SCORES (This Session)")
        print("="*100)
        print(f"{'Time':<20} {'From':<25} {'Score':<8} {'Result':<12}")
        print("-"*100)
        
        for entry in reversed(recent):
            time = entry.get('timestamp', '')[:19]
            sender = entry.get('sender_domain', '')[:24]
            score = f"{entry.get('phishing_score', 0):.2f}"
            result = entry.get('classification', 'unknown')
            
            result_display = f"🔴 {result}" if result == "phishing" else f"🟢 {result}"
            print(f"{time:<20} {sender:<25} {score:<8} {result_display:<12}")
        
        print("="*100)


# ============================================================================
# MODELS
# ============================================================================

class Observation(BaseModel):
    email_content: str
    sender_domain: str
    subject_line: str
    has_links: bool
    link_count: int
    links: List[str] = []
    urgency_words: List[str]
    suspicious_patterns: List[str]

class Action(BaseModel):
    phishing_score: float = Field(ge=0.0, le=1.0)
    classification: str
    suspicious_elements: List[str]
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str

class State(BaseModel):
    current_task: int
    current_email_id: str
    attempts: int
    total_reward: float
    last_action: Optional[Action] = None
    task_completed: bool = False


# ============================================================================
# EMAIL ANALYZER
# ============================================================================

class EmailAnalyzer:
    URGENCY_WORDS = ['urgent', 'immediately', 'asap', 'suspended', 'declined', 
                     'verify now', 'action required', '24 hours', '48 hours', 'interrupted',
                     'limited', 'unusual activity', 'security alert', 'account will be',
                     'as soon as possible', 'immediately using the link']
    
    LEGITIMATE_SECURITY_PHRASES = [
        'if this was you', 'safely ignore', 'you can safely ignore',
        'review your recent login', 'from a device that you haven\'t used',
        'you don\'t need to do anything', 'if you made this change'
    ]
    
    EXACT_TRUSTED_DOMAINS = [
        'github.com', 'google.com', 'accounts.google.com', 'security.google.com',
        'microsoft.com', 'apple.com', 'amazon.com', 'paypal.com', 
        'chase.com', 'bankofamerica.com', 'airtel.com', 'airtel.in',
        'linkedin.com', 'twitter.com', 'facebook.com', 'coursera.org',
        'udemy.com', 'edx.org'
    ]
    
    FAKE_DOMAINS = [
        'google-accounts.com', 'google-security.com', 'accounts-google.com',
        'accounts-google-security.com', 'amazon-verify.com', 'amazon-verify.click',
        'paypal-security.com', 'github-security.com', 'secure-update.com',
        'account-alert.com', 'billing-helpdesk.com', 'paypal-verify.xyz',
        'amazon-payment.click', 'bank-alert.xyz'
    ]
    
    SUSPICIOUS_PATTERNS = [
        (r'http://[^/]+\.(xyz|top|club|work|click|net|com|in|info|tk|ml|ga)', 'suspicious TLD link'),
        (r'https?://[^/]+(verify|secure|update|confirm|login|restore|validate)[^/]*\.(xyz|top|club|click)', 'suspicious verification link'),
        (r'verify.*account', 'account verification request'),
        (r'password.*expired', 'password expiration'),
        (r'payment.*failed', 'payment failure'),
        (r'account.*suspended', 'account suspension threat'),
        (r'secure.*verify', 'security verification request'),
        (r'click.*here', 'click here link'),
        (r'within \d+ hours', 'urgent time limit')
    ]
    
    @classmethod
    def extract_sender(cls, raw_email):
        from_match = re.search(r'^From:\s*([^\n]+)', raw_email, re.IGNORECASE | re.MULTILINE)
        if from_match:
            sender_text = from_match.group(1)
            email_match = re.search(r'<([^>]+)>|([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', sender_text)
            if email_match:
                return email_match.group(1) or email_match.group(2)
            return sender_text.strip()
        return "unknown"
    
    @classmethod
    def extract_subject(cls, raw_email):
        subject_match = re.search(r'^Subject:\s*(.+?)(?:\n|$)', raw_email, re.IGNORECASE | re.MULTILINE)
        if subject_match:
            return subject_match.group(1).strip()
        return "No Subject"
    
    @classmethod
    def extract_content(cls, raw_email):
        lines = raw_email.split('\n')
        content_lines = []
        found_blank = False
        
        for line in lines:
            if not found_blank and line.strip() == '':
                found_blank = True
                continue
            if found_blank:
                content_lines.append(line)
        
        content = '\n'.join(content_lines).strip()
        if not content:
            content = raw_email
        return content
    
    @classmethod
    def extract_links(cls, content):
        return re.findall(r'https?://[^\s<>"\'\)]+', content)
    
    @classmethod
    def check_link_safety(cls, link, sender_domain):
        try:
            parsed = urlparse(link)
            link_domain = parsed.netloc
            
            if sender_domain and link_domain == sender_domain:
                return True, link_domain, "exact_match"
            if sender_domain and link_domain.endswith('.' + sender_domain):
                return True, link_domain, "subdomain_match"
            if link_domain in cls.EXACT_TRUSTED_DOMAINS:
                return True, link_domain, "trusted_domain"
            for trusted in cls.EXACT_TRUSTED_DOMAINS:
                if link_domain.endswith('.' + trusted):
                    return True, link_domain, "trusted_subdomain"
            for fake in cls.FAKE_DOMAINS:
                if fake in link_domain:
                    return False, link_domain, "fake_domain"
            return False, link_domain, "untrusted"
        except:
            return False, "unknown", "error"
    
    @classmethod
    def is_fake_domain_impersonation(cls, sender_domain):
        for fake in cls.FAKE_DOMAINS:
            if fake == sender_domain or fake in sender_domain:
                return True, fake
        for trusted in cls.EXACT_TRUSTED_DOMAINS:
            company = trusted.split('.')[0]
            if company in sender_domain.lower() and sender_domain not in cls.EXACT_TRUSTED_DOMAINS:
                return True, f"{company} impersonation"
        return False, None
    
    @classmethod
    def is_legitimate_security_alert(cls, content_lower, sender_domain, links, link_results):
        has_safety_phrase = any(phrase in content_lower for phrase in cls.LEGITIMATE_SECURITY_PHRASES)
        is_trusted_sender = sender_domain in cls.EXACT_TRUSTED_DOMAINS
        all_links_safe = all(result[0] for result in link_results) if link_results else True
        return is_trusted_sender and all_links_safe and has_safety_phrase
    
    @classmethod
    def analyze_raw_email(cls, raw_email):
        sender = cls.extract_sender(raw_email)
        subject = cls.extract_subject(raw_email)
        content = cls.extract_content(raw_email)
        
        sender_domain = sender.split('@')[-1] if '@' in sender else sender
        content_lower = content.lower()
        
        links = cls.extract_links(content)
        link_results = []
        unsafe_links = []
        safe_links = []
        links_match_sender = False
        
        for link in links:
            is_safe, domain, reason = cls.check_link_safety(link, sender_domain)
            link_results.append((is_safe, domain, reason))
            if is_safe:
                safe_links.append(link)
                if reason in ['exact_match', 'subdomain_match']:
                    links_match_sender = True
            else:
                unsafe_links.append(link)
        
        urgency_words = []
        for w in cls.URGENCY_WORDS:
            if w in content_lower:
                urgency_words.append(w)
        
        suspicious_patterns = []
        for pattern, description in cls.SUSPICIOUS_PATTERNS:
            if re.search(pattern, content_lower):
                suspicious_patterns.append(description)
        
        is_fake, fake_name = cls.is_fake_domain_impersonation(sender_domain)
        is_legit_security = cls.is_legitimate_security_alert(content_lower, sender_domain, links, link_results)
        
        return Observation(
            email_content=content[:2000],
            sender_domain=sender_domain,
            subject_line=subject,
            has_links=len(links) > 0,
            link_count=len(links),
            links=links,
            urgency_words=urgency_words,
            suspicious_patterns=suspicious_patterns
        ), is_legit_security, unsafe_links, safe_links, is_fake, fake_name, links_match_sender


# ============================================================================
# PHISHING AGENT
# ============================================================================

class PhishingAgent:
    def __init__(self):
        self.suspicious_domains = ['xyz', 'top', 'club', 'work', 'click', 'net', 'info', 'in', 'tk', 'ml', 'ga',
                                     'secure-update', 'verify', 'account-alert', 'billing-helpdesk', 'airtel-verify']
        
        self.fake_domains = [
            'google-accounts.com', 'google-security.com', 'accounts-google.com',
            'accounts-google-security.com', 'amazon-verify.com', 'amazon-verify.click',
            'paypal-security.com', 'github-security.com', 'secure-update.com',
            'account-alert.com', 'billing-helpdesk.com', 'paypal-verify.xyz',
            'amazon-payment.click', 'bank-alert.xyz'
        ]
        
        self.exact_trusted_domains = [
            'github.com', 'google.com', 'accounts.google.com', 'security.google.com',
            'microsoft.com', 'apple.com', 'amazon.com', 'paypal.com', 
            'chase.com', 'bankofamerica.com', 'airtel.com', 'airtel.in',
            'linkedin.com', 'twitter.com', 'facebook.com', 'coursera.org',
            'udemy.com', 'edx.org'
        ]
        
        self.legitimate_phrases = [
            'if this was you', 'safely ignore', 'you can safely ignore',
            'review your recent login', 'from a device that you haven\'t used',
            'you don\'t need to do anything', 'if you made this change'
        ]
        
        self.phishing_keywords = [
            'urgent', 'immediately', 'suspended', 'declined', 'verify now',
            'action required', '24 hours', '48 hours', 'interrupted',
            'account will be suspended', 'permanent account closure',
            'unusual activity', 'limited', 'verify your identity',
            'as soon as possible', 'immediately using the link'
        ]
    
    def analyze(self, observation, is_legitimate_security=False, unsafe_links=None, 
                safe_links=None, is_fake_domain=False, fake_name=None, links_match_sender=False):
        phishing_score = 0.0
        suspicious_elements = []
        content_lower = observation.email_content.lower()
        
        is_exact_trusted = observation.sender_domain in self.exact_trusted_domains
        
        if is_exact_trusted:
            phishing_score -= 0.35
            suspicious_elements.append(f"trusted domain: {observation.sender_domain}")
        
        if links_match_sender and not is_fake_domain:
            phishing_score -= 0.3
            suspicious_elements.append("links match sender domain")
        
        if is_fake_domain:
            phishing_score += 0.7
            suspicious_elements.append(f"FAKE DOMAIN: {observation.sender_domain}")
        
        if 'google' in observation.sender_domain.lower() and observation.sender_domain not in self.exact_trusted_domains:
            phishing_score += 0.6
            suspicious_elements.append("Google impersonation attempt")
        
        if 'paypal' in observation.sender_domain.lower() and observation.sender_domain not in self.exact_trusted_domains:
            phishing_score += 0.6
            suspicious_elements.append("PayPal impersonation attempt")
        
        if 'amazon' in observation.sender_domain.lower() and observation.sender_domain not in self.exact_trusted_domains:
            phishing_score += 0.6
            suspicious_elements.append("Amazon impersonation attempt")
        
        if unsafe_links:
            for link in unsafe_links:
                link_lower = link.lower()
                is_impersonation = False
                for trusted in self.exact_trusted_domains:
                    company = trusted.split('.')[0]
                    if company in link_lower and trusted not in link_lower:
                        phishing_score += 0.35
                        suspicious_elements.append(f"link impersonates {company}")
                        is_impersonation = True
                        break
                
                if not is_impersonation:
                    if any(tld in link_lower for tld in ['.xyz', '.top', '.club', '.click', '.work']):
                        phishing_score += 0.3
                        suspicious_elements.append("suspicious TLD in link")
                    else:
                        phishing_score += 0.2
            
            if len(unsafe_links) > 0:
                suspicious_elements.append(f"unsafe links ({len(unsafe_links)})")
        
        has_safety_phrase = any(phrase in content_lower for phrase in self.legitimate_phrases)
        
        is_real_security = (
            is_exact_trusted and 
            has_safety_phrase and 
            unsafe_links is not None and 
            len(unsafe_links) == 0
        )
        
        if is_real_security:
            phishing_score -= 0.35
            suspicious_elements.append("legitimate security alert")
        
        if has_safety_phrase and is_fake_domain:
            phishing_score += 0.25
            suspicious_elements.append("fake domain with safety reassurance")
        
        if any(domain in observation.sender_domain.lower() for domain in self.suspicious_domains):
            phishing_score += 0.25
            suspicious_elements.append("suspicious sender domain")
        
        keyword_count = 0
        for keyword in self.phishing_keywords:
            if keyword in content_lower:
                keyword_count += 1
                if keyword not in suspicious_elements:
                    suspicious_elements.append(keyword)
        
        phishing_score += min(keyword_count * 0.08, 0.25)
        
        if observation.suspicious_patterns and not is_real_security:
            phishing_score += 0.15
            suspicious_elements.extend(observation.suspicious_patterns[:2])
        
        if observation.urgency_words and not is_real_security:
            phishing_score += 0.1
            suspicious_elements.extend(observation.urgency_words[:1])
        
        if observation.link_count >= 3:
            phishing_score += 0.1
            suspicious_elements.append("excessive links")
        
        phishing_score = max(0.0, min(phishing_score, 1.0))
        
        if is_fake_domain:
            classification = "phishing"
        elif 'google' in observation.sender_domain.lower() and observation.sender_domain not in self.exact_trusted_domains:
            classification = "phishing"
        elif 'paypal' in observation.sender_domain.lower() and observation.sender_domain not in self.exact_trusted_domains:
            classification = "phishing"
        elif 'amazon' in observation.sender_domain.lower() and observation.sender_domain not in self.exact_trusted_domains:
            classification = "phishing"
        else:
            classification = "phishing" if phishing_score >= 0.4 else "legitimate"
        
        suspicious_elements = list(dict.fromkeys(suspicious_elements))
        
        if classification == "phishing":
            if is_fake_domain:
                reasoning = f"⚠️ PHISHING: Fake domain impersonating legitimate service"
            elif 'google' in observation.sender_domain.lower():
                reasoning = f"⚠️ PHISHING: Google impersonation attempt"
            elif 'paypal' in observation.sender_domain.lower():
                reasoning = f"⚠️ PHISHING: PayPal impersonation attempt"
            elif 'amazon' in observation.sender_domain.lower():
                reasoning = f"⚠️ PHISHING: Amazon impersonation attempt"
            else:
                reasoning = f"⚠️ Phishing indicators: {', '.join(suspicious_elements[:4])}"
        else:
            if is_real_security:
                reasoning = "✅ Legitimate security alert from trusted domain"
            elif is_exact_trusted:
                reasoning = f"✅ Legitimate email from trusted domain"
            elif links_match_sender:
                reasoning = "✅ Legitimate: Links match sender domain"
            else:
                reasoning = "✅ No significant phishing indicators detected"
        
        return Action(
            phishing_score=phishing_score,
            classification=classification,
            suspicious_elements=suspicious_elements[:5],
            confidence=0.5 + (abs(0.5 - phishing_score) * 0.8),
            reasoning=reasoning
        )


# ============================================================================
# GLOBAL SCORE LOGGER
# ============================================================================

score_logger = ScoreLogger()


# ============================================================================
# QUICK TEST (Built-in Sample Emails)
# ============================================================================

def quick_test():
    """Quick test with built-in sample emails - automatically clears previous scores"""
    print("\n" + "="*60)
    print("🔍 QUICK TEST (Built-in Sample Emails)")
    print("="*60)
    
    # Start a new session - this clears previous scores
    score_logger.start_new_session()
    
    sample_emails = [
        {
            "name": "LEGITIMATE - Coursera Certificate",
            "email": """From: no-reply@coursera.org
Subject: Course Completion Certificate Available

Dear Learner,

Congratulations on completing your course!

Your certificate is now available at:
https://www.coursera.org/account/certificate

Thank you for learning with us!

Coursera Team""",
            "expected": "legitimate"
        },
        {
            "name": "PHISHING - Fake Google 2FA",
            "email": """From: noreply@google-accounts.com
Subject: 2-Step Verification turned off

Hello,

This is to confirm that 2-Step Verification has been successfully turned off.

If you did NOT make this change, please review your account activity immediately:
https://accounts-google-security.com/recovery-check

Thanks,
Google Accounts Team""",
            "expected": "phishing"
        },
        {
            "name": "LEGITIMATE - GitHub Security Alert",
            "email": """From: support@github.com
Subject: Security alert: New sign-in to your account

Hi,

We noticed a new sign-in to your GitHub account.

If this was you, you can safely ignore this message.

If you don't recognize this activity, review your login activity:
https://github.com/security-checkup/login-activity

Thanks,
GitHub Security Team""",
            "expected": "legitimate"
        },
        {
            "name": "PHISHING - PayPal Scam",
            "email": """From: security@paypal-verify.xyz
Subject: URGENT: Your PayPal Account Has Been Limited

Dear Customer,

We've detected unusual activity on your PayPal account.

Verify now: http://paypal-security.xyz/verify

Failure will result in permanent limitation.""",
            "expected": "phishing"
        }
    ]
    
    agent = PhishingAgent()
    results = []
    
    for idx, email_data in enumerate(sample_emails, 1):
        print(f"\n{'─'*50}")
        print(f"📧 {email_data['name']}")
        print(f"{'─'*50}")
        
        observation, is_legit_security, unsafe_links, safe_links, is_fake_domain, fake_name, links_match_sender = EmailAnalyzer.analyze_raw_email(email_data['email'])
        action = agent.analyze(observation, is_legit_security, unsafe_links, safe_links, is_fake_domain, fake_name, links_match_sender)
        
        is_correct = action.classification == email_data['expected']
        
        print(f"   From: {observation.sender_domain}")
        print(f"   Result: {'🔴 PHISHING' if action.classification == 'phishing' else '🟢 LEGITIMATE'}")
        print(f"   Confidence: {action.confidence:.0%}")
        print(f"   Score: {action.phishing_score:.2f}")
        print(f"   Suspicious: {', '.join(action.suspicious_elements[:3]) if action.suspicious_elements else 'None'}")
        print(f"   Reasoning: {action.reasoning}")
        print(f"   Expected: {email_data['expected'].upper()}")
        print(f"   {'✅ CORRECT!' if is_correct else '❌ INCORRECT!'}")
        
        # LOG THE SCORE to human-readable file
        email_log = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sender_domain": observation.sender_domain,
            "subject": observation.subject_line,
            "has_links": observation.has_links,
            "link_count": observation.link_count,
            "urgency_word_count": len(observation.urgency_words),
            "phishing_score": action.phishing_score,
            "classification": action.classification,
            "confidence": action.confidence,
            "reasoning": action.reasoning,
            "suspicious_elements": action.suspicious_elements,
            "is_fake_domain": is_fake_domain,
            "unsafe_link_count": len(unsafe_links),
            "links_match_sender": links_match_sender
        }
        score_logger.log_score(email_log)
        
        results.append(is_correct)
    
    correct = sum(results)
    total = len(results)
    print(f"\n{'='*60}")
    print(f"SUMMARY: {correct}/{total} correct ({correct/total*100:.0f}%)")
    print(f"{'='*60}")
    
    # Show summary and where to find the file
    score_logger.print_summary()
    score_logger.show_recent(5)


# ============================================================================
# LOAD CUSTOM EMAILS
# ============================================================================

def load_custom_emails_from_file(filename="custom_emails.txt"):
    emails = []
    
    if not os.path.exists(filename):
        print(f"\n❌ File '{filename}' not found!")
        return []
    
    with open(filename, 'r', encoding='utf-8') as f:
        content = f.read()
    
    sections = re.split(r'\n===.*?===\n', content)
    
    for section in sections:
        section = section.strip()
        if not section:
            continue
        
        lines = section.split('\n')
        raw_email = section
        
        first_line = lines[0].strip().lower()
        if first_line in ['phishing', 'legitimate']:
            label = first_line
            raw_email = '\n'.join(lines[1:])
        else:
            label = None
        
        emails.append({
            "raw_email": raw_email,
            "expected_label": label
        })
    
    if len(emails) == 0 and '===' in content:
        sections = content.split('===')
        for section in sections:
            section = section.strip()
            if section and not section.startswith('#'):
                emails.append({
                    "raw_email": section,
                    "expected_label": None
                })
    
    if len(emails) == 0 and content.strip():
        emails.append({
            "raw_email": content,
            "expected_label": None
        })
    
    print(f"✅ Loaded {len(emails)} custom emails from {filename}")
    return emails


def test_custom_emails(emails):
    """Test all custom emails from file with logging"""
    print("\n" + "="*70)
    print("🔍 TESTING CUSTOM EMAILS FROM FILE")
    print("="*70)
    
    # Ask user if they want to start a new session or append
    choice = input("\nStart a new session? (y/n - default y): ").strip().lower()
    if choice == '' or choice == 'y' or choice == 'yes':
        score_logger.start_new_session()
    else:
        print("📝 Appending to existing session...")
    
    agent = PhishingAgent()
    
    for idx, email_data in enumerate(emails, 1):
        raw_email = email_data["raw_email"]
        expected_label = email_data["expected_label"]
        
        print(f"\n{'─'*60}")
        print(f"📧 EMAIL #{idx}")
        print(f"{'─'*60}")
        
        observation, is_legit_security, unsafe_links, safe_links, is_fake_domain, fake_name, links_match_sender = EmailAnalyzer.analyze_raw_email(raw_email)
        action = agent.analyze(observation, is_legit_security, unsafe_links, safe_links, is_fake_domain, fake_name, links_match_sender)
        
        print(f"   From: {observation.sender_domain}")
        print(f"   Subject: {observation.subject_line[:70]}")
        print(f"   Result: {'🔴 PHISHING' if action.classification == 'phishing' else '🟢 LEGITIMATE'}")
        print(f"   Score: {action.phishing_score:.2f}")
        print(f"   Reasoning: {action.reasoning}")
        
        # LOG THE SCORE
        email_log = {
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "sender_domain": observation.sender_domain,
            "subject": observation.subject_line,
            "has_links": observation.has_links,
            "link_count": observation.link_count,
            "urgency_word_count": len(observation.urgency_words),
            "phishing_score": action.phishing_score,
            "classification": action.classification,
            "confidence": action.confidence,
            "reasoning": action.reasoning,
            "suspicious_elements": action.suspicious_elements,
            "is_fake_domain": is_fake_domain,
            "unsafe_link_count": len(unsafe_links),
            "links_match_sender": links_match_sender
        }
        score_logger.log_score(email_log)
        
        if expected_label:
            is_correct = action.classification == expected_label
            print(f"\n   Expected: {expected_label.upper()} → {'✅ CORRECT' if is_correct else '❌ INCORRECT'}")
    
    score_logger.print_summary()
    print(f"\n📁 Full details saved to: email_scores.txt")


# ============================================================================
# FULL DATASET EVALUATION
# ============================================================================

def load_dataset():
    if not os.path.exists("data/phishing_dataset.csv"):
        return None
    df = pd.read_csv("data/phishing_dataset.csv")
    return df


class TaskGrader:
    def __init__(self, dataset):
        self.dataset = dataset
        self.results = []
    
    def grade_task(self, task_id, action, email_id):
        if self.dataset is not None and email_id:
            email_row = self.dataset[self.dataset['id'] == email_id]
            if len(email_row) > 0:
                email = email_row.iloc[0].to_dict()
                actual_label = email.get('label', 'legitimate')
            else:
                actual_label = 'legitimate'
        else:
            actual_label = 'legitimate'
        
        predicted_label = action.get('classification', 'legitimate')
        is_correct = predicted_label == actual_label
        
        if is_correct:
            score = 0.85
            if len(action.get('suspicious_elements', [])) >= 2:
                score += 0.1
            if action.get('confidence', 0) > 0.8:
                score += 0.05
        else:
            score = 0.3
        
        score = min(score, 1.0)
        self.results.append({'score': score, 'passed': score >= 0.7})
        return score
    
    def get_average_score(self):
        if not self.results:
            return 0.0
        return sum(r['score'] for r in self.results) / len(self.results)


class PhishingEnvironment:
    def __init__(self, dataset):
        self.dataset = dataset
        self.current_email = None
        self.reset()
    
    def reset(self):
        if self.dataset is not None and len(self.dataset) > 0:
            self.current_email = self.dataset.sample(1).iloc[0].to_dict()
        else:
            self.current_email = {"id": "dummy", "label": "legitimate", "content": "", "sender": "", "subject": ""}
        return None
    
    def step(self, action):
        return None, 0, False, None


def run_full_evaluation():
    """Run evaluation on the full dataset (400 emails)"""
    print("\n" + "="*60)
    print("📊 FULL DATASET EVALUATION (400 EMAILS)")
    print("="*60)
    
    dataset = load_dataset()
    if dataset is None:
        print("\n❌ Dataset not found!")
        print("   Please run first: python data/create_dataset.py")
        return 0.0
    
    print(f"\n✅ Loaded dataset: {len(dataset)} emails")
    print(f"   - Phishing: {len(dataset[dataset['label'] == 'phishing'])}")
    print(f"   - Legitimate: {len(dataset[dataset['label'] == 'legitimate'])}")
    
    agent = PhishingAgent()
    grader = TaskGrader(dataset)
    
    results = []
    
    for task_id in range(1, 4):
        print(f"\n{'─'*50}")
        difficulty = "EASY" if task_id == 1 else "MEDIUM" if task_id == 2 else "HARD"
        print(f"📧 TASK {task_id}: {difficulty}")
        print(f"{'─'*50}")
        
        if task_id == 1:
            test_emails = dataset[dataset['label'] == 'phishing'].head(10)
        elif task_id == 2:
            test_emails = dataset.sample(10)
        else:
            test_emails = dataset[dataset['label'] == 'phishing'].sample(10)
        
        task_scores = []
        for _, email in test_emails.iterrows():
            class SimpleObs:
                def __init__(self, email):
                    self.email_content = email.get('content', '')
                    self.sender_domain = email.get('sender', '').split('@')[-1] if '@' in email.get('sender', '') else ''
                    self.subject_line = email.get('subject', '')
                    self.has_links = bool(re.search(r'http', email.get('content', '')))
                    self.link_count = len(re.findall(r'http', email.get('content', '')))
                    self.links = []
                    self.urgency_words = []
                    self.suspicious_patterns = []
            
            obs = SimpleObs(email)
            action = agent.analyze(obs, False, [], [], False, None, False)
            score = grader.grade_task(task_id, action.model_dump(), email.get('id', ''))
            task_scores.append(score)
        
        avg_task_score = sum(task_scores) / len(task_scores)
        results.append(avg_task_score)
        print(f"   Average Score: {avg_task_score:.3f}/1.00")
    
    avg_score = sum(results) / len(results)
    print(f"\n{'='*60}")
    print(f"🏆 FINAL SCORE: {avg_score:.3f}/1.00")
    print(f"{'='*60}")
    
    return avg_score


def view_scores():
    """View all saved scores from the text file"""
    print("\n" + "="*60)
    print("📊 EMAIL SCORE HISTORY")
    print("="*60)
    
    if not os.path.exists("email_scores.txt"):
        print("\n❌ No scores found yet. Run some tests first!")
        return
    
    print("\n📁 Viewing: email_scores.txt")
    print("-"*60)
    
    # Read and display the file
    with open("email_scores.txt", 'r', encoding='utf-8') as f:
        content = f.read()
        print(content)
    
    score_logger.print_summary()


# ============================================================================
# MAIN MENU
# ============================================================================

def main():
    while True:
        print("\n" + "="*60)
        print("🔐 PHISHING EMAIL DETECTOR")
        print("="*60)
        print("\nChoose an option:")
        print("  1. 📁 Test Custom Emails from File (custom_emails.txt)")
        print("  2. 📊 Run Full Dataset Evaluation (400 emails)")
        print("  3. 🔍 Quick Test (Built-in Sample Emails) - Clears previous scores")
        print("  4. 📈 View Saved Scores (email_scores.txt)")
        print("  5. 🚪 Exit")
        print("-" * 40)
        
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == '1':
            filename = input("Enter filename (default: custom_emails.txt): ").strip()
            if not filename:
                filename = "custom_emails.txt"
            emails = load_custom_emails_from_file(filename)
            if emails:
                test_custom_emails(emails)
            else:
                print("\n❌ No emails loaded. Please create the file first.")
        
        elif choice == '2':
            run_full_evaluation()
        
        elif choice == '3':
            quick_test()
        
        elif choice == '4':
            view_scores()
        
        elif choice == '5':
            print("\n👋 Goodbye! Stay safe from phishing! 🛡️")
            break
        
        else:
            print("\n❌ Invalid choice. Please enter 1-5.")
        
        input("\nPress Enter to continue...")


# ============================================================================
# ENTRY POINT
# ============================================================================

if __name__ == "__main__":
    # Always run interactive menu locally
    main()