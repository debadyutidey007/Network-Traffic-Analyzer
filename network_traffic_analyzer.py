import os
import sys
import re
import io
import csv
import json
import time
import atexit
import logging
import threading
import queue
import traceback
import configparser
from datetime import datetime, timedelta
from collections import defaultdict
from functools import wraps

# Flask and extensions
import flask
from flask import Flask, render_template as flask_render_template, redirect, url_for, flash, request
from flask import jsonify, send_from_directory, Response
from flask_socketio import SocketIO, emit
from flask_login import LoginManager, UserMixin, login_user, logout_user
from flask_login import login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

# Data processing and analysis
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

# Cryptography
from cryptography.fernet import Fernet

# Visualization
import matplotlib
matplotlib.use('Agg')  # Set the backend to Agg for non-GUI environments
import matplotlib.pyplot as plt

# PDF generation
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

# Initialize logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('analyzer_output.txt')
    ]
)

logger = logging.getLogger(__name__)

# Force demo mode, no packet capture libraries
PACKET_CAPTURE_AVAILABLE = False
logger.warning("Packet capture libraries not available - running in demo mode only")

# Disable TLS warnings 
TLS_AVAILABLE = False
logging.warning("TLS parsing is disabled.")

# Encryption for logs
ENCRYPTION_KEY = Fernet.generate_key()
cipher = Fernet(ENCRYPTION_KEY)

#==============================================================================
# Flask Application Setup
#==============================================================================
class Base(DeclarativeBase):
    pass
# Create Flask application
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET", "d3v3l0pm3nt_s3cr3t_k3y")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
# Ensure the templates and static directories exist
os.makedirs('templates', exist_ok=True)
os.makedirs('static', exist_ok=True)
os.makedirs('static/reports', exist_ok=True)
os.makedirs('static/js', exist_ok=True)
# Configure database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///network_analyzer.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
# Initialize extensions
db = SQLAlchemy(model_class=Base)
db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message_category = 'info'
socketio = SocketIO()
socketio.init_app(app, cors_allowed_origins="*")

#==============================================================================
# Database Models
#==============================================================================
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Incident(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    src_ip = db.Column(db.String(64))
    dst_ip = db.Column(db.String(64))
    protocol = db.Column(db.String(32))
    details = db.Column(db.Text)
    encrypted_log = db.Column(db.LargeBinary)
    severity = db.Column(db.String(32), default='medium')
    resolved = db.Column(db.Boolean, default=False)
    notes = db.Column(db.Text)
    
    def __repr__(self):
        return f'<Incident {self.id}: {self.src_ip} -> {self.dst_ip} ({self.protocol})>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'src_ip': self.src_ip,
            'dst_ip': self.dst_ip,
            'protocol': self.protocol,
            'details': self.details,
            'severity': self.severity,
            'resolved': self.resolved
        }

class AnalyzerConfig(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(64), unique=True, nullable=False)
    value = db.Column(db.Text)
    category = db.Column(db.String(64))
    description = db.Column(db.Text)
    
    def __repr__(self):
        return f'<Config {self.key}={self.value}>'

class BlockedIP(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(64), unique=True, nullable=False)
    reason = db.Column(db.Text)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    active = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', backref='blocked_ips')
    
    def __repr__(self):
        return f'<BlockedIP {self.ip_address}>'

class BlockedDomain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain = db.Column(db.String(128), unique=True, nullable=False)
    reason = db.Column(db.Text)
    added_at = db.Column(db.DateTime, default=datetime.utcnow)
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    active = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', backref='blocked_domains')
    
    def __repr__(self):
        return f'<BlockedDomain {self.domain}>'

class PacketStatistics(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    ip_address = db.Column(db.String(64))
    packet_count = db.Column(db.Integer, default=0)
    byte_count = db.Column(db.Integer, default=0)
    port_count = db.Column(db.Integer, default=0)
    is_anomaly = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<PacketStatistics {self.ip_address}: {self.packet_count} packets>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'ip_address': self.ip_address,
            'packet_count': self.packet_count,
            'byte_count': self.byte_count,
            'port_count': self.port_count,
            'is_anomaly': self.is_anomaly
        }

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(128))
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    generated_by = db.Column(db.Integer, db.ForeignKey('user.id'))
    file_path = db.Column(db.String(256))
    report_type = db.Column(db.String(64))
    
    user = db.relationship('User', backref='reports')
    
    def __repr__(self):
        return f'<Report {self.title}>'

#==============================================================================
# Analyzer Core
#==============================================================================
class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(contamination=0.1, random_state=42)
        self.features = []
        self.training_data = []
        self.is_trained = False
    
    def add_feature(self, packet_count, byte_size, port_variety):
        self.features.append([packet_count, byte_size, port_variety])
        if len(self.features) > 1000:
            self.train()
    
    def train(self):
        if len(self.features) > 100:
            self.training_data = np.array(self.features)
            self.model.fit(self.training_data)
            self.features = self.features[-100:]  # Keep last 100 for memory efficiency
            self.is_trained = True
            logger.info("Anomaly detection model retrained")
    
    def predict(self, feature):
        if not self.is_trained:
            return False
        return self.model.predict([feature])[0] == -1  # -1 indicates anomaly

class PacketAnalyzer:
    def __init__(self, config_path='analyzer_config.ini'):
        self.config = configparser.ConfigParser()
        self.config.read(config_path)
        
        self.packet_queue = queue.Queue()
        self.anomaly_detector = AnomalyDetector()
        self.packet_counts = defaultdict(int)
        self.byte_sizes = defaultdict(int)
        self.port_variety = defaultdict(set)
        self.blocklist = self.load_blocklist()
        self.incident_lock = threading.Lock()
        self.running = True
        self.start_time = datetime.now()
        self.packet_processor = None
        self.sniffer_thread = None
        self.statistics_thread = None
        self.total_packets_processed = 0
        
        # Initialize VT API key from config or environment
        self.vt_api_key = self.config.get('API', 'virustotal_key', fallback=os.environ.get('VT_API_KEY', ''))
        
        # Register cleanup on exit
        atexit.register(self.cleanup)
        
        # Force demo mode since packet capture isn't available on Windows without WinPcap/Npcap
        self.demo_mode = True
        logger.info("Running in demo mode with simulated traffic")
        
        # Create reports directory if it doesn't exist
        os.makedirs('static/reports', exist_ok=True)
    
    def load_blocklist(self):
        """Load blocklist from database."""
        try:
            blocklist = {
                'ip': set(),
                'domain': set()
            }
            
            # Get blocked IPs
            blocked_ips = BlockedIP.query.filter_by(active=True).all()
            for ip in blocked_ips:
                blocklist['ip'].add(ip.ip_address)
            
            # Get blocked domains
            blocked_domains = BlockedDomain.query.filter_by(active=True).all()
            for domain in blocked_domains:
                blocklist['domain'].add(domain.domain)
            
            logger.info(f"Loaded blocklist: {len(blocklist['ip'])} IPs, {len(blocklist['domain'])} domains")
            return blocklist
        except Exception as e:
            logger.error(f"Error loading blocklist: {str(e)}")
            return {'ip': set(), 'domain': set()}
    
    def reload_blocklist(self):
        """Reload blocklist from database."""
        self.blocklist = self.load_blocklist()
        return self.blocklist
    
    def check_threat_intel(self, domain):
        """Query VirusTotal for domain reputation."""
        try:
            if not self.vt_api_key:
                return False, "No VirusTotal API key configured"
            
            import requests
            headers = {
                'x-apikey': self.vt_api_key
            }
            
            response = requests.get(
                f'https://www.virustotal.com/api/v3/domains/{domain}',
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                # Check if domain has malicious flags
                analysis_stats = data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                malicious_count = analysis_stats.get('malicious', 0)
                
                if malicious_count > 0:
                    return True, f"VirusTotal reports {malicious_count} malicious flags"
            
            return False, "No threat information found"
        except Exception as e:
            logger.error(f"Error checking threat intelligence: {str(e)}")
            return False, f"Error checking threat intelligence: {str(e)}"
    
    def analyze_packet(self, pkt):
        """Analyze packet and queue for processing."""
        try:
            # Just queue the packet for processing in a separate thread
            if self.running:
                self.packet_queue.put(pkt)
                return True
            return False
        except Exception as e:
            logger.error(f"Error analyzing packet: {str(e)}")
            return False
    
    def process_packet(self):
        """Process packets from queue."""
        while self.running:
            try:
                # Generate demo packets - we're always in demo mode here
                self._generate_demo_packet()
                time.sleep(0.5)  # Simulate network traffic pace
            except Exception as e:
                logger.error(f"Error in packet processor: {str(e)}")
                traceback.print_exc()
    
    def _generate_demo_packet(self):
        """Generate a demo packet for demo mode."""
        try:
            # Create a synthetic "packet" with minimal data needed for demo
            time_now = datetime.now()
            
            # Randomize packet properties
            import random
            
            # Generate a random IP address
            src_ip = f"192.168.{random.randint(1, 254)}.{random.randint(1, 254)}"
            dst_ip = f"172.16.{random.randint(1, 254)}.{random.randint(1, 254)}"
            
            protocols = ['TCP', 'UDP', 'HTTP', 'DNS', 'HTTPS']
            protocol = random.choice(protocols)
            
            src_port = random.randint(1024, 65535)
            common_ports = [80, 443, 22, 53, 8080, 25, 110, 143]
            dst_port = random.choice(common_ports)
            
            # Randomly determine if this is a suspicious packet
            is_suspicious = random.random() < 0.1  # 10% chance
            
            # Generate a domain for DNS traffic
            domains = [
                "example.com", "google.com", "facebook.com", "amazon.com", 
                "microsoft.com", "apple.com", "netflix.com", "wikipedia.org"
            ]
            malicious_domains = [
                "malware-site.example", "phishing.example", "suspicious-domain.example"
            ]
            
            domain = random.choice(malicious_domains if is_suspicious else domains)
            
            # Create demo details
            details = f"Protocol: {protocol}, Src Port: {src_port}, Dst Port: {dst_port}"
            if protocol in ['DNS', 'HTTP', 'HTTPS']:
                details += f", Domain: {domain}"
            
            # Simulate abnormal traffic pattern sometimes
            abnormal_traffic = random.random() < 0.05  # 5% chance
            
            # Update statistics
            self.packet_counts[src_ip] += 1
            self.byte_sizes[src_ip] += random.randint(100, 1500)  # Random packet size
            self.port_variety[src_ip].add(dst_port)
            
            # Log packet
            self.total_packets_processed += 1
            
            # Check for anomalies
            if len(self.packet_counts) > 10:  # Wait until we have some data
                ports_count = len(self.port_variety[src_ip])
                packet_count = self.packet_counts[src_ip]
                byte_size = self.byte_sizes[src_ip]
                
                # Add features to anomaly detector
                self.anomaly_detector.add_feature(packet_count, byte_size, ports_count)
                
                # Force anomaly for demo if abnormal_traffic flag is set
                is_anomaly = abnormal_traffic
                
                # Log suspicious activity
                if is_suspicious or is_anomaly or src_ip in self.blocklist['ip'] or domain in self.blocklist['domain']:
                    severity = 'high' if is_anomaly else 'medium' if is_suspicious else 'low'
                    reason = []
                    
                    if is_anomaly:
                        reason.append("Anomalous traffic pattern")
                    if is_suspicious:
                        reason.append("Suspicious activity")
                    if src_ip in self.blocklist['ip']:
                        reason.append("IP in blocklist")
                    if domain in self.blocklist['domain']:
                        reason.append("Domain in blocklist")
                    
                    self.log_incident(
                        time_now,
                        src_ip,
                        dst_ip,
                        protocol,
                        f"{details}, Reason: {', '.join(reason)}",
                        severity
                    )
            
            # Periodically save statistics to database
            if self.total_packets_processed % 20 == 0:
                self._save_statistics(src_ip)
            
        except Exception as e:
            logger.error(f"Error generating demo packet: {str(e)}")
            traceback.print_exc()
    
    def _save_statistics(self, ip_address):
        """Save statistics to database."""
        try:
            with app.app_context():
                # Add statistics to database
                stat = PacketStatistics(
                    timestamp=datetime.now(),
                    ip_address=ip_address,
                    packet_count=self.packet_counts[ip_address],
                    byte_count=self.byte_sizes[ip_address],
                    port_count=len(self.port_variety[ip_address]),
                    is_anomaly=False  # Set based on anomaly detection
                )
                
                db.session.add(stat)
                db.session.commit()
        except Exception as e:
            logger.error(f"Error saving statistics: {str(e)}")
            db.session.rollback()
    
    def is_suspicious_url(self, url):
        """Check for suspicious URL patterns."""
        suspicious_patterns = [
            r'\.tk$',  # Free TK domain, often abused
            r'\.xyz$',  # Cheap domain, often abused
            r'\.top$',  # Cheap domain, often abused
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # IP address in URL
            r'bit\.ly',  # URL shorteners often used in phishing
            r'goo\.gl',
            r'tinyurl',
            r'(password|login|bank|account|security|update|verify).*\.(php|aspx|jsp)',  # Suspicious auth pages
            r'[0-9a-f]{30,}',  # Long hex strings may be encoded data
            r'[a-zA-Z0-9]{16,}\.[a-z]{2,4}/[a-zA-Z0-9]{10,}',  # Random looking URLs
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                return True
        
        return False
    
    def log_incident(self, timestamp, src_ip, dst_ip, protocol, details, severity='medium'):
        """Log incident to database with encryption."""
        try:
            # Encrypt sensitive details
            encrypted_log = cipher.encrypt(details.encode('utf-8'))
            
            with self.incident_lock:
                incident = Incident(
                    timestamp=timestamp,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    protocol=protocol,
                    details=details,
                    encrypted_log=encrypted_log,
                    severity=severity
                )
                
                db.session.add(incident)
                db.session.commit()
                
                # Emit to socket.io
                socketio.emit('new_incident', incident.to_dict())
                
                logger.info(f"Incident logged: {src_ip} -> {dst_ip} ({protocol}): {details}")
        except Exception as e:
            logger.error(f"Error logging incident: {str(e)}")
            db.session.rollback()
    
    def generate_report(self, report_type='general', user_id=None):
        """Generate visualization of incidents and PDF report."""
        try:
            # Create filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"report_{report_type}_{timestamp}.pdf"
            filepath = os.path.join('static/reports', filename)
            
            # Get data based on report type
            if report_type == 'incidents':
                incidents = Incident.query.order_by(Incident.timestamp.desc()).limit(100).all()
                title = "Recent Security Incidents"
            elif report_type == 'traffic':
                stats = PacketStatistics.query.order_by(PacketStatistics.timestamp.desc()).limit(100).all()
                title = "Network Traffic Analysis"
            elif report_type == 'anomaly':
                anomalies = PacketStatistics.query.filter_by(is_anomaly=True).order_by(PacketStatistics.timestamp.desc()).limit(50).all()
                incidents = Incident.query.filter_by(severity='high').order_by(Incident.timestamp.desc()).limit(50).all()
                title = "Anomaly Detection Report"
            else:
                # General report
                incidents = Incident.query.order_by(Incident.timestamp.desc()).limit(50).all()
                stats = PacketStatistics.query.order_by(PacketStatistics.timestamp.desc()).limit(50).all()
                blocked = BlockedIP.query.filter_by(active=True).all()
                title = "Network Security Overview"
            
            # Initialize PDF document
            doc = SimpleDocTemplate(filepath, pagesize=letter)
            elements = []
            styles = getSampleStyleSheet()
            
            # Add title and timestamp
            elements.append(Paragraph(title, styles['Title']))
            elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
            elements.append(Spacer(1, 12))
            
            # Add summary information
            elements.append(Paragraph("Summary Information", styles['Heading2']))
            
            # Count incidents by severity
            severity_counts = db.session.query(
                Incident.severity, db.func.count(Incident.id).label('count')
            ).group_by(Incident.severity).all()
            
            severity_data = [['Severity', 'Count']]
            for severity, count in severity_counts:
                severity_data.append([severity.title(), count])
            
            if len(severity_data) > 1:
                elements.append(Paragraph("Incidents by Severity", styles['Heading3']))
                elements.append(Spacer(1, 6))
                
                # Create table
                severity_table = Table(severity_data)
                severity_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 12),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                    ('GRID', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                elements.append(severity_table)
                elements.append(Spacer(1, 12))
            
            # Create incidents chart
            if 'incidents' in locals():
                elements.append(Paragraph("Recent Incidents", styles['Heading3']))
                elements.append(Spacer(1, 6))
                
                # Format incident data for table
                incident_data = [['Time', 'Source IP', 'Protocol', 'Severity', 'Details']]
                for incident in incidents[:20]:  # Limit to 20 for readability
                    incident_data.append([
                        incident.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                        incident.src_ip,
                        incident.protocol,
                        incident.severity.title(),
                        incident.details[:50] + ('...' if len(incident.details) > 50 else '')
                    ])
                
                if len(incident_data) > 1:
                    incident_table = Table(incident_data, colWidths=[80, 80, 60, 60, 200])
                    incident_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                        ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (-1, 0), 12),
                        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                        ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                        ('GRID', (0, 0), (-1, -1), 1, colors.black),
                        ('WORDWRAP', (4, 1), (4, -1), True)
                    ]))
                    
                    elements.append(incident_table)
                    elements.append(Spacer(1, 12))
                
                # Graph for protocol distribution
                protocols = {}
                for incident in incidents:
                    if incident.protocol not in protocols:
                        protocols[incident.protocol] = 0
                    protocols[incident.protocol] += 1
                
                if protocols:
                    plt.figure(figsize=(8, 5))
                    plt.bar(protocols.keys(), protocols.values(), color='skyblue')
                    plt.title('Incidents by Protocol')
                    plt.xlabel('Protocol')
                    plt.ylabel('Count')
                    plt.xticks(rotation=45)
                    plt.tight_layout()
                    
                    # Save chart to a file
                    chart_path = 'static/reports/protocol_chart.png'
                    plt.savefig(chart_path)
                    plt.close()
                    
                    # Add chart to PDF
                    elements.append(Paragraph("Protocol Distribution", styles['Heading3']))
                    elements.append(Spacer(1, 6))
                    elements.append(Image(chart_path, width=400, height=250))
                    elements.append(Spacer(1, 12))
            
            # Build PDF
            doc.build(elements)
            
            # Save report to database
            report = Report(
                title=title,
                generated_by=user_id,
                file_path=filename,
                report_type=report_type
            )
            
            db.session.add(report)
            db.session.commit()
            
            logger.info(f"Report generated: {filepath}")
            return filename
            
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            traceback.print_exc()
            return None
    
    def update_statistics(self):
        """Update and emit statistics periodically."""
        while self.running:
            try:
                # Aggregate statistics for active IPs
                stats = []
                for ip, count in self.packet_counts.items():
                    if count > 0:
                        stats.append({
                            'ip_address': ip,
                            'packet_count': count,
                            'byte_count': self.byte_sizes[ip],
                            'port_count': len(self.port_variety[ip]),
                            'timestamp': datetime.now().isoformat()
                        })
                
                # Emit statistics update
                if stats:
                    socketio.emit('statistics_update', {'stats': stats})
                
                # Sleep for update interval
                time.sleep(5)
                
            except Exception as e:
                logger.error(f"Error updating statistics: {str(e)}")
            
    def start(self):
        """Start the packet analyzer threads."""
        if not self.running:
            self.running = True
            self.start_time = datetime.now()
            
            # Start packet processor thread (only demo mode)
            self.packet_processor = threading.Thread(target=self.process_packet)
            self.packet_processor.daemon = True
            self.packet_processor.start()
            
            # Start statistics thread
            self.statistics_thread = threading.Thread(target=self.update_statistics)
            self.statistics_thread.daemon = True
            self.statistics_thread.start()
            
            # Log that we're running in demo mode
            logger.info("Running in demo mode (using simulated traffic)")
            socketio.emit('analyzer_status', {'status': 'running'})
    
    def stop(self):
        """Stop the packet analyzer."""
        if self.running:
            self.running = False
            logger.info("Stopping packet analyzer...")
            
            # Generate final report
            try:
                with app.app_context():
                    self.generate_report('general')
            except Exception as e:
                logger.error(f"Error generating final report: {str(e)}")
            
            # Emit status update
            socketio.emit('analyzer_status', {'status': 'stopped'})
            
            # Clear packet queue
            while not self.packet_queue.empty():
                try:
                    self.packet_queue.get_nowait()
                except queue.Empty:
                    break
                self.packet_queue.task_done()
            
            logger.info("Packet analyzer stopped successfully")
    
    def cleanup(self):
        """Cleanup resources on exit."""
        try:
            if self.running:
                self.stop()
        except Exception as e:
            logger.error(f"Error during cleanup: {str(e)}")
# Singleton instance of packet analyzer
_analyzer = None

def get_analyzer():
    """Return singleton instance of packet analyzer."""
    global _analyzer
    if _analyzer is None:
        _analyzer = PacketAnalyzer()
    return _analyzer

#==============================================================================
# Route helpers
#==============================================================================
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Helper for admin-only routes
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            flash('You need administrator privileges to access this page.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

def update_config_file():
    """Update analyzer config file from database."""
    config = configparser.ConfigParser()
    
    # Get all configurations
    configs = AnalyzerConfig.query.all()
    
    # Group by category
    config_by_category = {}
    for cfg in configs:
        if cfg.category not in config_by_category:
            config_by_category[cfg.category] = {}
        config_by_category[cfg.category][cfg.key] = cfg.value
    
    # Add to config
    for category, values in config_by_category.items():
        config[category] = values
    
    # Write to file
    with open('analyzer_config.ini', 'w') as f:
        config.write(f)

#==============================================================================
# Templates
#==============================================================================
TEMPLATES = {
    'base.html': '''<!DOCTYPE html>
<html lang="en" data-bs-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Network Traffic Analyzer</title>
    <!-- Bootstrap CSS -->
    <link href="https://cdn.replit.com/agent/bootstrap-agent-dark-theme.min.css" rel="stylesheet">
    <!-- Font Awesome -->
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css" rel="stylesheet">
    <!-- Chart.js -->
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <!-- Socket.IO -->
    <script src="https://cdn.socket.io/4.4.1/socket.io.min.js"></script>
    <!-- Custom CSS -->
    <style>
        body 
        {
            padding-top: 56px;
            min-height: 100vh;
            display: flex;
            flex-direction: column;
        }
        
        .sidebar 
        {
            min-height: calc(100vh - 56px);
            background-color: var(--bs-dark);
            border-right: 1px solid var(--bs-gray-700);
        }
        
        .main-content 
        {
            flex: 1;
            padding: 20px;
        }
        
        .card 
        {
            margin-bottom: 20px;
            border: none;
            box-shadow: 0 0.125rem 0.25rem rgba(0, 0, 0, 0.075);
            background-color: var(--bs-dark);
        }
        
        .chart-container 
        {
            position: relative;
            height: 300px;
            width: 100%;
        }
        
        .incident-high 
        {
            background-color: rgba(255, 99, 132, 0.1) !important;
        }
        
        .incident-medium 
        {
            background-color: rgba(255, 206, 86, 0.1) !important;
        }
        
        .incident-low 
        {
            background-color: rgba(75, 192, 192, 0.1) !important;
        }
        
        .footer 
        {
            padding: 20px 0;
            margin-top: auto;
            background-color: var(--bs-dark);
            border-top: 1px solid var(--bs-gray-700);
        }
    </style>
</head>
<body>
    <!-- Navbar -->
    <nav class="navbar navbar-expand-lg navbar-dark bg-dark fixed-top">
        <div class="container-fluid">
            <a class="navbar-brand" href="{{ url_for('dashboard') }}">
                <i class="fas fa-shield-alt me-2"></i>Network Traffic Analyzer
            </a>
            <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav">
                <span class="navbar-toggler-icon"></span>
            </button>
            <div class="collapse navbar-collapse" id="navbarNav">
                <ul class="navbar-nav">
                    {% if current_user.is_authenticated %}
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('dashboard') }}">
                            <i class="fas fa-tachometer-alt me-1"></i>Dashboard
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('incidents') }}">
                            <i class="fas fa-exclamation-triangle me-1"></i>Incidents
                        </a>
                    </li>
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('reports') }}">
                            <i class="fas fa-chart-bar me-1"></i>Reports
                        </a>
                    </li>
                    {% if current_user.is_admin %}
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('config') }}">
                            <i class="fas fa-cogs me-1"></i>Configuration
                        </a>
                    </li>
                    {% endif %}
                    {% endif %}
                </ul>
                <ul class="navbar-nav ms-auto">
                    {% if current_user.is_authenticated %}
                    <li class="nav-item">
                        <span class="nav-link text-info" id="analyzer-status-indicator">
                            <i class="fas fa-circle text-{{ 'success' if analyzer_running else 'danger' }} me-1"></i>
                            {{ 'Running' if analyzer_running else 'Stopped' }}
                        </span>
                    </li>
                    <li class="nav-item dropdown">
                        <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown">
                            <i class="fas fa-user-circle me-1"></i>{{ current_user.username }}
                        </a>
                        <ul class="dropdown-menu dropdown-menu-end">
                            <li><a class="dropdown-item" href="{{ url_for('logout') }}">Logout</a></li>
                        </ul>
                    </li>
                    {% else %}
                    <li class="nav-item">
                        <a class="nav-link" href="{{ url_for('login') }}">Login</a>
                    </li>
                    {% endif %}
                </ul>
            </div>
        </div>
    </nav>
    <!-- Main content -->
    <div class="container-fluid">
        <div class="row">
            {% if current_user.is_authenticated %}
            <div class="col-md-2 d-none d-md-block sidebar py-3">
                <div class="list-group">
                    <a href="{{ url_for('dashboard') }}" class="list-group-item list-group-item-action bg-transparent border-0">
                        <i class="fas fa-tachometer-alt me-2"></i>Dashboard
                    </a>
                    <a href="{{ url_for('incidents') }}" class="list-group-item list-group-item-action bg-transparent border-0">
                        <i class="fas fa-exclamation-triangle me-2"></i>Incidents
                    </a>
                    <a href="{{ url_for('reports') }}" class="list-group-item list-group-item-action bg-transparent border-0">
                        <i class="fas fa-chart-bar me-2"></i>Reports
                    </a>
                    {% if current_user.is_admin %}
                    <a href="{{ url_for('config') }}" class="list-group-item list-group-item-action bg-transparent border-0">
                        <i class="fas fa-cogs me-2"></i>Configuration
                    </a>
                    <a href="{{ url_for('register') }}" class="list-group-item list-group-item-action bg-transparent border-0">
                        <i class="fas fa-user-plus me-2"></i>Add User
                    </a>
                    {% endif %}
                </div>
            </div>
            <div class="col-md-10 ms-sm-auto px-md-4 main-content">
            {% else %}
            <div class="col-12 main-content">
            {% endif %}
                <!-- Flash messages -->
                {% with messages = get_flashed_messages(with_categories=true) %}
                    {% if messages %}
                        {% for category, message in messages %}
                            <div class="alert alert-{{ category }} alert-dismissible fade show" role="alert">
                                {{ message }}
                                <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
                            </div>
                        {% endfor %}
                    {% endif %}
                {% endwith %}
                
                <!-- Content from child templates -->
                {% block content %}{% endblock %}
            </div>
        </div>
    </div>
    <!-- Footer -->
    <footer class="footer text-center">
        <div class="container">
            <span class="text-muted">Network Traffic Analyzer &copy; {{ current_year }} | Built with ML-powered threat detection</span>
        </div>
    </footer>
    <!-- Bootstrap JS -->
    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.2.3/dist/js/bootstrap.bundle.min.js"></script>
    
    <!-- Common JS -->
    <script src="/static/js/socket.js"></script>
    <script src="/static/js/chart-utils.js"></script>
    
    <!-- Page-specific JS -->
    {% block scripts %}{% endblock %}
</body>
</html>''',
    
    'login.html': '''{% extends "base.html" %}
{% block content %}
<div class="row justify-content-center">
    <div class="col-md-6 col-lg-4">
        <div class="card mt-5">
            <div class="card-body">
                <h2 class="card-title text-center mb-4">
                    <i class="fas fa-shield-alt text-info me-2"></i>Login
                </h2>
                <form method="POST">
                    <div class="mb-3">
                        <label for="username" class="form-label">Username</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="fas fa-user"></i></span>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                    </div>
                    <div class="mb-3">
                        <label for="password" class="form-label">Password</label>
                        <div class="input-group">
                            <span class="input-group-text"><i class="fas fa-lock"></i></span>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                    </div>
                    <div class="d-grid gap-2">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-sign-in-alt me-2"></i>Login
                        </button>
                    </div>
                </form>
                <div class="mt-3 text-center small">
                    <p class="text-muted">Default credentials: admin/admin</p>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}''',
    
    'register.html': '''{% extends "base.html" %}
{% block content %}
<div class="container">
    <h2 class="mb-4"><i class="fas fa-user-plus me-2"></i>Register New User</h2>
    
    <div class="row">
        <div class="col-md-8">
            <div class="card">
                <div class="card-body">
                    <form method="POST">
                        <div class="mb-3">
                            <label for="username" class="form-label">Username</label>
                            <input type="text" class="form-control" id="username" name="username" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="email" class="form-label">Email</label>
                            <input type="email" class="form-control" id="email" name="email" required>
                        </div>
                        
                        <div class="mb-3">
                            <label for="password" class="form-label">Password</label>
                            <input type="password" class="form-control" id="password" name="password" required>
                        </div>
                        
                        <div class="mb-3 form-check">
                            <input type="checkbox" class="form-check-input" id="is_admin" name="is_admin">
                            <label class="form-check-label" for="is_admin">Admin Privileges</label>
                        </div>
                        
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-save me-2"></i>Register User
                        </button>
                    </form>
                </div>
            </div>
        </div>
        
        <div class="col-md-4">
            <div class="card">
                <div class="card-header bg-info text-white">
                    <i class="fas fa-info-circle me-2"></i>Information
                </div>
                <div class="card-body">
                    <p>Create a new user account with the specified permissions.</p>
                    <p>Users with admin privileges will be able to:</p>
                    <ul>
                        <li>Configure analyzer settings</li>
                        <li>Manage blocked IPs and domains</li>
                        <li>Register new users</li>
                        <li>Start/stop the analyzer</li>
                    </ul>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}''',
    
    'dashboard.html': '''{% extends "base.html" %}
{% block content %}
<div class="container-fluid">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="fas fa-tachometer-alt me-2"></i>Dashboard</h2>
        
        {% if current_user.is_admin %}
        <div class="btn-group">
            <button id="start-analyzer" class="btn btn-success" {{ 'disabled' if analyzer_running else '' }}>
                <i class="fas fa-play me-1"></i>Start Analyzer
            </button>
            <button id="stop-analyzer" class="btn btn-danger" {{ 'disabled' if not analyzer_running else '' }}>
                <i class="fas fa-stop me-1"></i>Stop Analyzer
            </button>
        </div>
        {% endif %}
    </div>
    
    <!-- Status Cards -->
    <div class="row mb-4">
        <div class="col-md-3">
            <div class="card">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <h6 class="card-title text-muted">Analyzer Status</h6>
                            <h3 class="mb-0" id="analyzer-display-status">
                                <span class="text-{{ 'success' if analyzer_running else 'danger' }}">
                                    {{ 'Running' if analyzer_running else 'Stopped' }}
                                </span>
                            </h3>
                        </div>
                        <div id="analyzer-display-icon">
                            <i class="fas fa-{{ 'play-circle text-success' if analyzer_running else 'stop-circle text-danger' }} fa-3x"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-md-3">
            <div class="card">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <h6 class="card-title text-muted">High Severity</h6>
                            <h3 class="mb-0 text-danger">{{ severity_counts.high }}</h3>
                        </div>
                        <div>
                            <i class="fas fa-radiation-alt fa-3x text-danger"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-md-3">
            <div class="card">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <h6 class="card-title text-muted">Medium Severity</h6>
                            <h3 class="mb-0 text-warning">{{ severity_counts.medium }}</h3>
                        </div>
                        <div>
                            <i class="fas fa-exclamation-triangle fa-3x text-warning"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-md-3">
            <div class="card">
                <div class="card-body">
                    <div class="d-flex justify-content-between align-items-center">
                        <div>
                            <h6 class="card-title text-muted">Low Severity</h6>
                            <h3 class="mb-0 text-info">{{ severity_counts.low }}</h3>
                        </div>
                        <div>
                            <i class="fas fa-info-circle fa-3x text-info"></i>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Charts Row -->
    <div class="row mb-4">
        <div class="col-md-4">
            <div class="card">
                <div class="card-header">
                    <h5 class="card-title mb-0">Protocol Distribution</h5>
                </div>
                <div class="card-body">
                    <div class="chart-container">
                        <canvas id="protocolChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-md-4">
            <div class="card">
                <div class="card-header">
                    <h5 class="card-title mb-0">Incident Timeline</h5>
                </div>
                <div class="card-body">
                    <div class="chart-container">
                        <canvas id="timelineChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-md-4">
            <div class="card">
                <div class="card-header">
                    <h5 class="card-title mb-0">Incidents by Severity</h5>
                </div>
                <div class="card-body">
                    <div class="chart-container">
                        <canvas id="severityChart"></canvas>
                    </div>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Live Traffic and Recent Incidents -->
    <div class="row">
        <div class="col-md-4">
            <div class="card">
                <div class="card-header">
                    <h5 class="card-title mb-0">
                        <i class="fas fa-stream me-2"></i>Live Traffic
                    </h5>
                </div>
                <div class="card-body">
                    <div id="live-traffic-stats">
                        <div class="text-center">
                            <div class="spinner-border text-primary" role="status">
                                <span class="visually-hidden">Loading...</span>
                            </div>
                            <p class="mt-2">Waiting for traffic data...</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <div class="col-md-8">
            <div class="card">
                <div class="card-header">
                    <div class="d-flex justify-content-between align-items-center">
                        <h5 class="card-title mb-0">
                            <i class="fas fa-exclamation-triangle me-2"></i>Recent Incidents
                        </h5>
                        <a href="{{ url_for('incidents') }}" class="btn btn-sm btn-outline-info">
                            View All
                        </a>
                    </div>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>Time</th>
                                    <th>Source IP</th>
                                    <th>Protocol</th>
                                    <th>Severity</th>
                                    <th>Details</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody id="incidents-table-body">
                                {% for incident in recent_incidents %}
                                <tr class="incident-{{ incident.severity }}">
                                    <td>{{ incident.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                                    <td>{{ incident.src_ip }}</td>
                                    <td>{{ incident.protocol }}</td>
                                    <td>
                                        <span class="badge bg-{{ 'danger' if incident.severity == 'high' else 'warning' if incident.severity == 'medium' else 'info' }}">
                                            {{ incident.severity|capitalize }}
                                        </span>
                                    </td>
                                    <td>{{ incident.details }}</td>
                                    <td>
                                        <a href="{{ url_for('incident_detail', id=incident.id) }}" class="btn btn-sm btn-outline-info">
                                            <i class="fas fa-eye"></i>
                                        </a>
                                    </td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
{% block scripts %}
<script src="/static/js/dashboard.js"></script>
{% endblock %}''',
    
    'incidents.html': '''{% extends "base.html" %}
{% block content %}
<div class="container-fluid">
    <h2 class="mb-4"><i class="fas fa-exclamation-triangle me-2"></i>Security Incidents</h2>
    
    <!-- Filter card -->
    <div class="card mb-4">
        <div class="card-header">
            <h5 class="card-title mb-0">Filters</h5>
        </div>
        <div class="card-body">
            <form method="GET" class="row g-3">
                <div class="col-md-3">
                    <label for="severity" class="form-label">Severity</label>
                    <select class="form-select" id="severity" name="severity">
                        <option value="">All</option>
                        <option value="high" {{ 'selected' if request.args.get('severity') == 'high' else '' }}>High</option>
                        <option value="medium" {{ 'selected' if request.args.get('severity') == 'medium' else '' }}>Medium</option>
                        <option value="low" {{ 'selected' if request.args.get('severity') == 'low' else '' }}>Low</option>
                    </select>
                </div>
                
                <div class="col-md-3">
                    <label for="protocol" class="form-label">Protocol</label>
                    <select class="form-select" id="protocol" name="protocol">
                        <option value="">All</option>
                        {% for protocol in protocols %}
                        <option value="{{ protocol }}" {{ 'selected' if request.args.get('protocol') == protocol else '' }}>{{ protocol }}</option>
                        {% endfor %}
                    </select>
                </div>
                
                <div class="col-md-3">
                    <label for="src_ip" class="form-label">Source IP</label>
                    <input type="text" class="form-control" id="src_ip" name="src_ip" value="{{ request.args.get('src_ip', '') }}">
                </div>
                
                <div class="col-md-3">
                    <label for="resolved" class="form-label">Status</label>
                    <select class="form-select" id="resolved" name="resolved">
                        <option value="">All</option>
                        <option value="no" {{ 'selected' if request.args.get('resolved') == 'no' else '' }}>Open</option>
                        <option value="yes" {{ 'selected' if request.args.get('resolved') == 'yes' else '' }}>Resolved</option>
                    </select>
                </div>
                
                <div class="col-12">
                    <div class="float-end">
                        <a href="{{ url_for('incidents') }}" class="btn btn-secondary">Reset</a>
                        <button type="submit" class="btn btn-primary">Apply Filters</button>
                    </div>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Incidents table -->
    <div class="card">
        <div class="card-header">
            <div class="d-flex justify-content-between align-items-center">
                <h5 class="card-title mb-0">Incidents</h5>
                
                <div class="btn-group">
                    <a href="{{ url_for('api_export_incidents', format='csv') }}" class="btn btn-sm btn-outline-secondary">
                        <i class="fas fa-file-csv me-1"></i>Export CSV
                    </a>
                    <a href="{{ url_for('api_export_incidents', format='json') }}" class="btn btn-sm btn-outline-secondary">
                        <i class="fas fa-file-code me-1"></i>Export JSON
                    </a>
                </div>
            </div>
        </div>
        <div class="card-body">
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Timestamp</th>
                            <th>Source IP</th>
                            <th>Destination IP</th>
                            <th>Protocol</th>
                            <th>Severity</th>
                            <th>Details</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for incident in incidents.items %}
                        <tr class="incident-{{ incident.severity }}">
                            <td>{{ incident.id }}</td>
                            <td>{{ incident.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                            <td>{{ incident.src_ip }}</td>
                            <td>{{ incident.dst_ip }}</td>
                            <td>{{ incident.protocol }}</td>
                            <td>
                                <span class="badge bg-{{ 'danger' if incident.severity == 'high' else 'warning' if incident.severity == 'medium' else 'info' }}">
                                    {{ incident.severity|capitalize }}
                                </span>
                            </td>
                            <td>{{ incident.details[:50] }}{{ '...' if incident.details|length > 50 else '' }}</td>
                            <td>
                                <span class="badge bg-{{ 'success' if incident.resolved else 'secondary' }}">
                                    {{ 'Resolved' if incident.resolved else 'Open' }}
                                </span>
                            </td>
                            <td>
                                <a href="{{ url_for('incident_detail', id=incident.id) }}" class="btn btn-sm btn-outline-info">
                                    <i class="fas fa-eye"></i>
                                </a>
                            </td>
                        </tr>
                        {% else %}
                        <tr>
                            <td colspan="9" class="text-center">No incidents found</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            
            <!-- Pagination -->
            {% if incidents.pages > 1 %}
            <nav aria-label="Page navigation">
                <ul class="pagination justify-content-center">
                    {% if incidents.has_prev %}
                    <li class="page-item">
                        <a class="page-link" href="{{ url_for('incidents', page=incidents.prev_num, **request.args) }}" aria-label="Previous">
                            <span aria-hidden="true">&laquo;</span>
                        </a>
                    </li>
                    {% else %}
                    <li class="page-item disabled">
                        <a class="page-link" href="#" aria-label="Previous">
                            <span aria-hidden="true">&laquo;</span>
                        </a>
                    </li>
                    {% endif %}
                    
                    {% for page_num in incidents.iter_pages(left_edge=1, right_edge=1, left_current=2, right_current=2) %}
                        {% if page_num %}
                            {% if page_num == incidents.page %}
                            <li class="page-item active">
                                <a class="page-link" href="#">{{ page_num }}</a>
                            </li>
                            {% else %}
                            <li class="page-item">
                                <a class="page-link" href="{{ url_for('incidents', page=page_num, **request.args) }}">{{ page_num }}</a>
                            </li>
                            {% endif %}
                        {% else %}
                        <li class="page-item disabled">
                            <a class="page-link" href="#">...</a>
                        </li>
                        {% endif %}
                    {% endfor %}
                    
                    {% if incidents.has_next %}
                    <li class="page-item">
                        <a class="page-link" href="{{ url_for('incidents', page=incidents.next_num, **request.args) }}" aria-label="Next">
                            <span aria-hidden="true">&raquo;</span>
                        </a>
                    </li>
                    {% else %}
                    <li class="page-item disabled">
                        <a class="page-link" href="#" aria-label="Next">
                            <span aria-hidden="true">&raquo;</span>
                        </a>
                    </li>
                    {% endif %}
                </ul>
            </nav>
            {% endif %}
        </div>
    </div>
</div>
{% endblock %}''',
    
    'incident_detail.html': '''{% extends "base.html" %}
{% block content %}
<div class="container-fluid">
    <div class="d-flex justify-content-between align-items-center mb-4">
        <h2><i class="fas fa-exclamation-triangle me-2"></i>Incident Details</h2>
        
        <div>
            <a href="{{ url_for('incidents') }}" class="btn btn-secondary">
                <i class="fas fa-arrow-left me-1"></i>Back to Incidents
            </a>
        </div>
    </div>
    
    <div class="row">
        <div class="col-md-8">
            <!-- Incident details card -->
            <div class="card mb-4">
                <div class="card-header bg-{{ 'danger' if incident.severity == 'high' else 'warning' if incident.severity == 'medium' else 'info' }} text-white">
                    <div class="d-flex justify-content-between align-items-center">
                        <h5 class="card-title mb-0">
                            <i class="fas {{ 'fa-radiation-alt' if incident.severity == 'high' else 'fa-exclamation-triangle' if incident.severity == 'medium' else 'fa-info-circle' }} me-2"></i>
                            {{ incident.severity|capitalize }} Severity Incident #{{ incident.id }}
                        </h5>
                        <span class="badge bg-light text-dark">
                            {{ incident.timestamp.strftime('%Y-%m-%d %H:%M:%S') }}
                        </span>
                    </div>
                </div>
                <div class="card-body">
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <h6 class="text-muted">Source IP</h6>
                            <p class="lead">{{ incident.src_ip }}</p>
                        </div>
                        <div class="col-md-6">
                            <h6 class="text-muted">Destination IP</h6>
                            <p class="lead">{{ incident.dst_ip }}</p>
                        </div>
                    </div>
                    
                    <div class="row mb-3">
                        <div class="col-md-6">
                            <h6 class="text-muted">Protocol</h6>
                            <p class="lead">{{ incident.protocol }}</p>
                        </div>
                        <div class="col-md-6">
                            <h6 class="text-muted">Status</h6>
                            <p class="lead">
                                <span class="badge bg-{{ 'success' if incident.resolved else 'secondary' }}">
                                    {{ 'Resolved' if incident.resolved else 'Open' }}
                                </span>
                            </p>
                        </div>
                    </div>
                    
                    <div class="row mb-3">
                        <div class="col-12">
                            <h6 class="text-muted">Details</h6>
                            <div class="p-3 bg-dark border border-secondary rounded">
                                <pre class="mb-0"><code>{{ incident.details }}</code></pre>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Notes and resolution card -->
            <div class="card">
                <div class="card-header">
                    <h5 class="card-title mb-0">Notes & Resolution</h5>
                </div>
                <div class="card-body">
                    <form method="POST">
                        <div class="mb-3">
                            <label for="notes" class="form-label">Incident Notes</label>
                            <textarea class="form-control" id="notes" name="notes" rows="5">{{ incident.notes or '' }}</textarea>
                        </div>
                        
                        <div class="mb-3 form-check">
                            <input type="checkbox" class="form-check-input" id="resolved" name="resolved" {{ 'checked' if incident.resolved else '' }}>
                            <label class="form-check-label" for="resolved">Mark as Resolved</label>
                        </div>
                        
                        {% if current_user.is_admin %}
                        <div class="mb-3 form-check">
                            <input type="checkbox" class="form-check-input" id="block_src_ip" name="block_src_ip">
                            <label class="form-check-label" for="block_src_ip">Block Source IP Address</label>
                            <small class="form-text text-muted d-block">Add the source IP ({{ incident.src_ip }}) to the blocklist</small>
                        </div>
                        {% endif %}
                        
                        <div class="text-end">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-save me-1"></i>Save Changes
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        
        <div class="col-md-4">
            <!-- Recommended actions card -->
            <div class="card mb-4">
                <div class="card-header">
                    <h5 class="card-title mb-0">
                        <i class="fas fa-shield-alt me-2"></i>Recommended Actions
                    </h5>
                </div>
                <div class="card-body">
                    <ul class="list-group list-group-flush">
                        {% if incident.severity == 'high' %}
                        <li class="list-group-item bg-transparent">
                            <i class="fas fa-ban text-danger me-2"></i>
                            Block source IP address immediately
                        </li>
                        <li class="list-group-item bg-transparent">
                            <i class="fas fa-search text-info me-2"></i>
                            Investigate all traffic from this source
                        </li>
                        <li class="list-group-item bg-transparent">
                            <i class="fas fa-file-alt text-warning me-2"></i>
                            Generate full incident report
                        </li>
                        {% elif incident.severity == 'medium' %}
                        <li class="list-group-item bg-transparent">
                            <i class="fas fa-search text-info me-2"></i>
                            Monitor additional traffic from this source
                        </li>
                        <li class="list-group-item bg-transparent">
                            <i class="fas fa-user-shield text-warning me-2"></i>
                            Verify security controls are in place
                        </li>
                        {% else %}
                        <li class="list-group-item bg-transparent">
                            <i class="fas fa-eye text-info me-2"></i>
                            Monitor for pattern establishment
                        </li>
                        {% endif %}
                    </ul>
                </div>
            </div>
            
            <!-- IP Information card -->
            <div class="card mb-4">
                <div class="card-header">
                    <h5 class="card-title mb-0">
                        <i class="fas fa-info-circle me-2"></i>IP Information
                    </h5>
                </div>
                <div class="card-body">
                    <p class="mb-2">
                        <strong>Source IP:</strong> {{ incident.src_ip }}
                    </p>
                    
                    <div class="d-grid gap-2">
                        <a href="https://www.abuseipdb.com/check/{{ incident.src_ip }}" target="_blank" class="btn btn-sm btn-outline-primary">
                            <i class="fas fa-external-link-alt me-1"></i>Check on AbuseIPDB
                        </a>
                        <a href="https://www.virustotal.com/gui/ip-address/{{ incident.src_ip }}" target="_blank" class="btn btn-sm btn-outline-primary">
                            <i class="fas fa-external-link-alt me-1"></i>Check on VirusTotal
                        </a>
                    </div>
                </div>
            </div>
            
            <!-- Related incidents card -->
            <div class="card">
                <div class="card-header">
                    <h5 class="card-title mb-0">
                        <i class="fas fa-link me-2"></i>Related Incidents
                    </h5>
                </div>
                <div class="card-body">
                    <ul class="list-group list-group-flush">
                        {% set related_incidents = Incident.query.filter_by(src_ip=incident.src_ip).filter(Incident.id != incident.id).order_by(Incident.timestamp.desc()).limit(5).all() %}
                        
                        {% if related_incidents %}
                            {% for related in related_incidents %}
                            <li class="list-group-item bg-transparent">
                                <div class="d-flex justify-content-between align-items-center">
                                    <a href="{{ url_for('incident_detail', id=related.id) }}" class="text-decoration-none">
                                        <span class="badge bg-{{ 'danger' if related.severity == 'high' else 'warning' if related.severity == 'medium' else 'info' }} me-2">
                                            {{ related.severity|capitalize }}
                                        </span>
                                        <small>{{ related.timestamp.strftime('%Y-%m-%d %H:%M') }}</small>
                                    </a>
                                </div>
                            </li>
                            {% endfor %}
                        {% else %}
                            <li class="list-group-item bg-transparent text-muted">
                                No related incidents found.
                            </li>
                        {% endif %}
                    </ul>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}''',
    
    'config.html': '''{% extends "base.html" %}
{% block content %}
<div class="container-fluid">
    <h2 class="mb-4"><i class="fas fa-cogs me-2"></i>Configuration</h2>
    
    <div class="row">
        <div class="col-md-8">
            <!-- Configuration card -->
            <div class="card mb-4">
                <div class="card-header">
                    <h5 class="card-title mb-0">Analyzer Settings</h5>
                </div>
                <div class="card-body">
                    <form method="POST">
                        {% for category, configs in configurations.items() %}
                        <h5 class="mt-3 mb-3">{{ category }} Configuration</h5>
                        
                        {% for config in configs %}
                        <div class="mb-3">
                            <label for="config_{{ config.id }}" class="form-label">{{ config.key }}</label>
                            <input type="text" class="form-control" id="config_{{ config.id }}" name="config_{{ config.id }}" value="{{ config.value }}" placeholder="{{ config.description }}">
                            <div class="form-text text-muted">{{ config.description }}</div>
                        </div>
                        {% endfor %}
                        
                        <hr>
                        {% endfor %}
                        
                        <div class="text-end">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-save me-1"></i>Save Configuration
                            </button>
                        </div>
                    </form>
                </div>
            </div>
        </div>
        
        <div class="col-md-4">
            <!-- Blocklist card -->
            <div class="card mb-4">
                <div class="card-header">
                    <h5 class="card-title mb-0">
                        <i class="fas fa-ban me-2"></i>Blocklist
                    </h5>
                </div>
                <div class="card-body">
                    <h6>Block IP Address</h6>
                    <form method="POST" action="{{ url_for('block_ip') }}" class="mb-4">
                        <div class="mb-3">
                            <label for="ip_address" class="form-label">IP Address</label>
                            <input type="text" class="form-control" id="ip_address" name="ip_address" required placeholder="e.g. 192.168.1.1">
                        </div>
                        
                        <div class="mb-3">
                            <label for="ip_reason" class="form-label">Reason</label>
                            <input type="text" class="form-control" id="ip_reason" name="reason" placeholder="Reason for blocking">
                        </div>
                        
                        <div class="d-grid">
                            <button type="submit" class="btn btn-danger">
                                <i class="fas fa-ban me-1"></i>Block IP
                            </button>
                        </div>
                    </form>
                    
                    <h6>Block Domain</h6>
                    <form method="POST" action="{{ url_for('block_domain') }}">
                        <div class="mb-3">
                            <label for="domain" class="form-label">Domain</label>
                            <input type="text" class="form-control" id="domain" name="domain" required placeholder="e.g. malicious-example.com">
                        </div>
                        
                        <div class="mb-3">
                            <label for="domain_reason" class="form-label">Reason</label>
                            <input type="text" class="form-control" id="domain_reason" name="reason" placeholder="Reason for blocking">
                        </div>
                        
                        <div class="d-grid">
                            <button type="submit" class="btn btn-danger">
                                <i class="fas fa-ban me-1"></i>Block Domain
                            </button>
                        </div>
                    </form>
                </div>
            </div>
            
            <!-- Blocked items card -->
            <div class="card">
                <div class="card-header">
                    <h5 class="card-title mb-0">Blocked Items</h5>
                </div>
                <div class="card-body">
                    <ul class="nav nav-tabs" id="blockedTabs" role="tablist">
                        <li class="nav-item" role="presentation">
                            <button class="nav-link active" id="ip-tab" data-bs-toggle="tab" data-bs-target="#ip-tab-pane" type="button" role="tab" aria-controls="ip-tab-pane" aria-selected="true">IPs</button>
                        </li>
                        <li class="nav-item" role="presentation">
                            <button class="nav-link" id="domain-tab" data-bs-toggle="tab" data-bs-target="#domain-tab-pane" type="button" role="tab" aria-controls="domain-tab-pane" aria-selected="false">Domains</button>
                        </li>
                    </ul>
                    
                    <div class="tab-content" id="blockedTabsContent">
                        <div class="tab-pane fade show active" id="ip-tab-pane" role="tabpanel" aria-labelledby="ip-tab" tabindex="0">
                            <div class="table-responsive mt-3">
                                <table class="table table-sm table-hover">
                                    <thead>
                                        <tr>
                                            <th>IP</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for ip in blocked_ips %}
                                        <tr>
                                            <td>{{ ip.ip_address }}</td>
                                            <td>
                                                <a href="{{ url_for('unblock_ip', id=ip.id) }}" class="btn btn-sm btn-outline-success">
                                                    <i class="fas fa-check"></i>
                                                </a>
                                            </td>
                                        </tr>
                                        {% else %}
                                        <tr>
                                            <td colspan="2" class="text-center">No blocked IPs</td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                        
                        <div class="tab-pane fade" id="domain-tab-pane" role="tabpanel" aria-labelledby="domain-tab" tabindex="0">
                            <div class="table-responsive mt-3">
                                <table class="table table-sm table-hover">
                                    <thead>
                                        <tr>
                                            <th>Domain</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {% for domain in blocked_domains %}
                                        <tr>
                                            <td>{{ domain.domain }}</td>
                                            <td>
                                                <a href="{{ url_for('unblock_domain', id=domain.id) }}" class="btn btn-sm btn-outline-success">
                                                    <i class="fas fa-check"></i>
                                                </a>
                                            </td>
                                        </tr>
                                        {% else %}
                                        <tr>
                                            <td colspan="2" class="text-center">No blocked domains</td>
                                        </tr>
                                        {% endfor %}
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}''',
    
    'reports.html': '''{% extends "base.html" %}
{% block content %}
<div class="container-fluid">
    <h2 class="mb-4"><i class="fas fa-chart-bar me-2"></i>Reports</h2>
    
    <div class="row">
        <div class="col-md-4">
            <!-- Generate report card -->
            <div class="card mb-4">
                <div class="card-header">
                    <h5 class="card-title mb-0">
                        <i class="fas fa-file-alt me-2"></i>Generate Report
                    </h5>
                </div>
                <div class="card-body">
                    <form id="report-form" method="POST" action="{{ url_for('generate_report') }}">
                        <div class="mb-3">
                            <label for="report_type" class="form-label">Report Type</label>
                            <select class="form-select" id="report_type" name="report_type" required>
                                <option value="general">General Overview</option>
                                <option value="incidents">Security Incidents</option>
                                <option value="traffic">Traffic Analysis</option>
                                <option value="anomaly">Anomaly Detection</option>
                            </select>
                        </div>
                        
                        <div class="d-grid">
                            <button type="submit" class="btn btn-primary">
                                <i class="fas fa-download me-1"></i>Generate Report
                            </button>
                        </div>
                    </form>
                </div>
            </div>
            
            <!-- Report explanation card -->
            <div class="card">
                <div class="card-header bg-info text-white">
                    <h5 class="card-title mb-0">
                        <i class="fas fa-info-circle me-2"></i>About Reports
                    </h5>
                </div>
                <div class="card-body">
                    <p>Reports provide detailed analysis of network traffic and security incidents.</p>
                    
                    <h6 class="mt-3">Report Types:</h6>
                    <ul class="list-unstyled">
                        <li>
                            <i class="fas fa-file-alt text-primary me-2"></i>
                            <strong>General Overview</strong>
                            <p class="text-muted small">Complete overview of network security status.</p>
                        </li>
                        <li>
                            <i class="fas fa-exclamation-triangle text-warning me-2"></i>
                            <strong>Security Incidents</strong>
                            <p class="text-muted small">Detailed analysis of recent security incidents.</p>
                        </li>
                        <li>
                            <i class="fas fa-chart-line text-success me-2"></i>
                            <strong>Traffic Analysis</strong>
                            <p class="text-muted small">Analysis of network traffic patterns.</p>
                        </li>
                        <li>
                            <i class="fas fa-search text-danger me-2"></i>
                            <strong>Anomaly Detection</strong>
                            <p class="text-muted small">Focus on detected anomalies and potential threats.</p>
                        </li>
                    </ul>
                </div>
            </div>
        </div>
        
        <div class="col-md-8">
            <!-- Recent reports card -->
            <div class="card">
                <div class="card-header">
                    <h5 class="card-title mb-0">
                        <i class="fas fa-history me-2"></i>Recent Reports
                    </h5>
                </div>
                <div class="card-body">
                    <div class="table-responsive">
                        <table class="table table-hover">
                            <thead>
                                <tr>
                                    <th>Title</th>
                                    <th>Type</th>
                                    <th>Generated</th>
                                    <th>User</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {% for report in reports %}
                                <tr>
                                    <td>{{ report.title }}</td>
                                    <td>
                                        <span class="badge bg-{{ 'primary' if report.report_type == 'general' else 'warning' if report.report_type == 'incidents' else 'success' if report.report_type == 'traffic' else 'danger' }}">
                                            {{ report.report_type|capitalize }}
                                        </span>
                                    </td>
                                    <td>{{ report.generated_at.strftime('%Y-%m-%d %H:%M:%S') }}</td>
                                    <td>{{ report.user.username if report.user else 'System' }}</td>
                                    <td>
                                        <a href="{{ url_for('download_report', filename=report.file_path) }}" class="btn btn-sm btn-outline-primary" data-bs-toggle="tooltip" data-bs-placement="top" title="Download">
                                            <i class="fas fa-download"></i>
                                        </a>
                                    </td>
                                </tr>
                                {% else %}
                                <tr>
                                    <td colspan="5" class="text-center">No reports generated yet</td>
                                </tr>
                                {% endfor %}
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}
{% block scripts %}
<script src="/static/js/reports.js"></script>
{% endblock %}''',
    
    'error.html': '''{% extends "base.html" %}
{% block content %}
<div class="container mt-5">
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card">
                <div class="card-header bg-danger text-white">
                    <h4 class="mb-0"><i class="fas fa-exclamation-triangle me-2"></i>Error</h4>
                </div>
                <div class="card-body">
                    <p class="lead">An error occurred while processing your request.</p>
                    
                    <div class="alert alert-danger">
                        <h5><i class="fas fa-bug me-2"></i>Error details:</h5>
                        <p>{{ error }}</p>
                    </div>
                    
                    <div class="text-center mt-4">
                        <a href="{{ url_for('dashboard') }}" class="btn btn-primary">
                            <i class="fas fa-home me-2"></i>Return to Dashboard
                        </a>
                    </div>
                </div>
            </div>
        </div>
    </div>
</div>
{% endblock %}'''
}

#==============================================================================
# Export static files to disk
#==============================================================================
def export_static_files():
    """Export all JavaScript files and templates to the respective directories."""
    # Export JavaScript files
    for filename, content in STATIC_JS.items():
        with open(f'static/js/{filename}', 'w') as f:
            f.write(content)
    
    # Export templates to the templates directory
    for template_name, content in TEMPLATES.items():
        with open(f'templates/{template_name}', 'w') as f:
            f.write(content)

#==============================================================================
# Static JavaScript
#==============================================================================
STATIC_JS = {
    # Chart utilities
    'chart-utils.js': '''
/**
 * Utility functions for charts and data visualization
 */
function getChartColors(count = 10) 
{
    // Collection of colors for charts
    const colors = [
        'rgba(54, 162, 235, 0.8)',    // blue
        'rgba(255, 99, 132, 0.8)',    // red
        'rgba(255, 206, 86, 0.8)',    // yellow
        'rgba(75, 192, 192, 0.8)',    // green
        'rgba(153, 102, 255, 0.8)',   // purple
        'rgba(255, 159, 64, 0.8)',    // orange
        'rgba(199, 199, 199, 0.8)',   // gray
        'rgba(83, 102, 255, 0.8)',    // indigo
        'rgba(78, 205, 196, 0.8)',    // teal
        'rgba(255, 99, 71, 0.8)',     // tomato
    ];
    // If more colors are needed, generate them
    if (count <= colors.length) 
    {
        return colors.slice(0, count);
    }
    // Generate additional colors
    const additionalColors = [];
    for (let i = 0; i < count - colors.length; i++) 
    {
        const r = Math.floor(Math.random() * 255);
        const g = Math.floor(Math.random() * 255);
        const b = Math.floor(Math.random() * 255);
        additionalColors.push(`rgba(${r}, ${g}, ${b}, 0.8)`);
    }
    return [...colors, ...additionalColors];
}
function formatNumber(num) 
{
    if (num >= 1000000) 
    {
        return (num / 1000000).toFixed(1) + 'M';
    }
    if (num >= 1000) 
    {
        return (num / 1000).toFixed(1) + 'K';
    }
    return num;
}
function formatBytes(bytes, decimals = 2) 
{
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}
function formatTimestamp(timestamp) 
{
    const date = new Date(timestamp);
    return date.toLocaleString();
}
''',
    
    # Dashboard JavaScript
    'dashboard.js': '''
/**
 * Dashboard-specific JavaScript functions
 */
document.addEventListener('DOMContentLoaded', function() {
    // Initialize charts
    let protocolChart = null;
    let timelineChart = null;
    let severityChart = null;
    
    // Initialize event listeners for admin controls
    if (document.getElementById('start-analyzer')) 
    {
        document.getElementById('start-analyzer').addEventListener('click', startAnalyzer);
    }
    
    if (document.getElementById('stop-analyzer')) 
    {
        document.getElementById('stop-analyzer').addEventListener('click', stopAnalyzer);
    }
    
    // Load initial chart data
    refreshCharts();
    
    // Set up real-time updates via Socket.IO
    if (window.socket) 
    {
        // Listen for status updates
        window.socket.on('analyzer_status', function(data) 
        {
            updateAnalyzerStatus(data.status);
        });
        
        // Listen for new incidents
        window.socket.on('new_incident', function(incident) 
        {
            updateIncidentTable(incident);
            // Also refresh charts when we get new data
            refreshCharts();
        });
        
        // Request recent incidents
        window.socket.emit('request_incidents');
        
        // Update incident table when we receive incident data
        window.socket.on('incidents_update', function(incidents) 
        {
            updateIncidentsTable(incidents);
        });
    }
    
    // Periodically refresh charts
    setInterval(refreshCharts, 30000); // Every 30 seconds
    
    /**
     * Refresh all charts with latest data
     */
    function refreshCharts() 
    {
        // Fetch protocol distribution data
        fetch('/api/stats/protocols')
            .then(response => response.json())
            .then(data => {
                updateProtocolChart(data.labels, data.data);
            })
            .catch(error => console.error('Error fetching protocol stats:', error));
        
        // Fetch timeline data
        fetch('/api/stats/timeline')
            .then(response => response.json())
            .then(data => {
                updateTimelineChart(data.labels, data.data);
            })
            .catch(error => console.error('Error fetching timeline stats:', error));
        
        // Fetch severity distribution data
        fetch('/api/stats/severity')
            .then(response => response.json())
            .then(data => {
                updateSeverityChart(data.labels, data.data);
            })
            .catch(error => console.error('Error fetching severity stats:', error));
    }
    
    /**
     * Update the protocol distribution chart
     */
    function updateProtocolChart(labels, data)
    {
        const ctx = document.getElementById('protocolChart').getContext('2d');
        
        // Destroy existing chart if it exists
        if (protocolChart) 
        {
            protocolChart.destroy();
        }
        
        // Create new chart
        protocolChart = new Chart(ctx, {
            type: 'pie',
            data: 
            {
                labels: labels,
                datasets: [{
                    data: data,
                    backgroundColor: getChartColors(labels.length),
                    borderWidth: 1
                }]
            },
            options: 
            {
                responsive: true,
                maintainAspectRatio: false,
                plugins: 
                {
                    legend: 
                    {
                        position: 'right',
                    },
                    title: 
                    {
                        display: true,
                        text: 'Incidents by Protocol'
                    }
                }
            }
        });
    }
    
    /**
     * Update the timeline chart
     */
    function updateTimelineChart(labels, data) 
    {
        const ctx = document.getElementById('timelineChart').getContext('2d');
        
        // Destroy existing chart if it exists
        if (timelineChart) 
        {
            timelineChart.destroy();
        }
        
        // Create new chart
        timelineChart = new Chart(ctx, {
            type: 'line',
            data: 
            {
                labels: labels,
                datasets: [{
                    label: 'Incidents',
                    data: data,
                    borderColor: 'rgba(54, 162, 235, 1)',
                    backgroundColor: 'rgba(54, 162, 235, 0.2)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: 
            {
                responsive: true,
                maintainAspectRatio: false,
                scales: 
                {
                    y: 
                    {
                        beginAtZero: true,
                        ticks: 
                        {
                            precision: 0
                        }
                    }
                },
                plugins: 
                {
                    title: 
                    {
                        display: true,
                        text: 'Incident Timeline (Last 24 Hours)'
                    }
                }
            }
        });
    }
    
    /**
     * Update the severity distribution chart
     */
    function updateSeverityChart(labels, data) 
    {
        if (!document.getElementById('severityChart')) 
        {
            return;  // Chart element doesn't exist
        }
        
        const ctx = document.getElementById('severityChart').getContext('2d');
        
        // Map severity levels to colors
        const backgroundColors = labels.map(label => {
            if (label.toLowerCase() === 'high') return 'rgba(255, 99, 132, 0.8)';
            if (label.toLowerCase() === 'medium') return 'rgba(255, 206, 86, 0.8)';
            return 'rgba(75, 192, 192, 0.8)';
        });
        
        // Destroy existing chart if it exists
        if (severityChart) 
        {
            severityChart.destroy();
        }
        
        // Create new chart
        severityChart = new Chart(ctx, {
            type: 'bar',
            data: 
            {
                labels: labels.map(l => l.charAt(0).toUpperCase() + l.slice(1)),
                datasets: [{
                    label: 'Incidents',
                    data: data,
                    backgroundColor: backgroundColors,
                    borderColor: backgroundColors.map(color => color.replace('0.8', '1')),
                    borderWidth: 1
                }]
            },
            options: 
            {
                responsive: true,
                maintainAspectRatio: false,
                scales: 
                {
                    y: 
                    {
                        beginAtZero: true,
                        ticks: 
                        {
                            precision: 0
                        }
                    }
                },
                plugins: 
                {
                    title: 
                    {
                        display: true,
                        text: 'Incidents by Severity'
                    }
                }
            }
        });
    }
    
    /**
     * Update the analyzer status display
     */
    function updateAnalyzerStatus(status) 
    {
        const statusDisplay = document.getElementById('analyzer-display-status');
        const iconDisplay = document.getElementById('analyzer-display-icon');
        const startButton = document.getElementById('start-analyzer');
        const stopButton = document.getElementById('stop-analyzer');
        
        if (!statusDisplay || !iconDisplay) return;
        
        if (status === 'running') 
        {
            statusDisplay.innerHTML = '<span class="text-success">Running</span>';
            iconDisplay.innerHTML = '<i class="fas fa-play-circle text-success fa-3x"></i>';
            
            if (startButton && stopButton) 
            {
                startButton.disabled = true;
                stopButton.disabled = false;
            }
        } 
        else 
        {
            statusDisplay.innerHTML = '<span class="text-danger">Stopped</span>';
            iconDisplay.innerHTML = '<i class="fas fa-stop-circle text-danger fa-3x"></i>';
            
            if (startButton && stopButton) 
            {
                startButton.disabled = false;
                stopButton.disabled = true;
            }
        }
    }
    
    /**
     * Start the analyzer
     */
    function startAnalyzer() 
    {
        fetch('/api/start_analyzer', {
            method: 'POST',
            headers: 
            {
                'Content-Type': 'application/json',
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'running') {
                updateAnalyzerStatus('running');
            }
        })
        .catch(error => console.error('Error starting analyzer:', error));
    }
    
    /**
     * Stop the analyzer
     */
    function stopAnalyzer() 
    {
        fetch('/api/stop_analyzer', {
            method: 'POST',
            headers: 
            {
                'Content-Type': 'application/json',
            }
        })
        .then(response => response.json())
        .then(data => {
            if (data.status === 'stopped') {
                updateAnalyzerStatus('stopped');
            }
        })
        .catch(error => console.error('Error stopping analyzer:', error));
    }
    
    /**
     * Update the incidents table with a new incident
     */
    function updateIncidentTable(incident) 
    {
        const tableBody = document.getElementById('incidents-table-body');
        if (!tableBody) return;
        
        // Format the timestamp
        const timestamp = new Date(incident.timestamp);
        const formattedTimestamp = timestamp.toLocaleString();
        
        // Create badge for severity
        let severityBadge = '';
        if (incident.severity === 'high') 
        {
            severityBadge = '<span class="badge bg-danger">High</span>';
        } 
        else if (incident.severity === 'medium') 
        {
            severityBadge = '<span class="badge bg-warning">Medium</span>';
        } 
        else 
        {
            severityBadge = '<span class="badge bg-info">Low</span>';
        }
        
        // Create new row HTML
        const newRow = document.createElement('tr');
        newRow.className = `incident-${incident.severity}`;
        newRow.innerHTML = `
            <td>${formattedTimestamp}</td>
            <td>${incident.src_ip}</td>
            <td>${incident.protocol}</td>
            <td>${severityBadge}</td>
            <td>${incident.details}</td>
            <td>
                <a href="/incidents/${incident.id}" class="btn btn-sm btn-outline-info">
                    <i class="fas fa-eye"></i>
                </a>
            </td>
        `;
        
        // Add to the beginning of the table
        if (tableBody.firstChild) 
        {
            tableBody.insertBefore(newRow, tableBody.firstChild);
        } 
        else 
        {
            tableBody.appendChild(newRow);
        }
        
        // Remove the last row if we have too many rows
        if (tableBody.children.length > 10) 
        {
            tableBody.removeChild(tableBody.lastChild);
        }
    }
    
    /**
     * Update the incidents table with multiple incidents
     */
    function updateIncidentsTable(incidents) 
    {
        const tableBody = document.getElementById('incidents-table-body');
        if (!tableBody) return;
        
        // Clear existing entries
        tableBody.innerHTML = '';
        
        // Add each incident
        incidents.forEach(incident => {
            updateIncidentTable(incident);
        });
    }
});
''',
    
    # Socket.IO handling
    'socket.js': '''
/**
 * Socket.IO connection and event handling
 */
document.addEventListener('DOMContentLoaded', function() {
    if (typeof io !== 'undefined') 
    {
        // Connect to Socket.IO server
        const socket = io();
        
        // Store socket in window for global access
        window.socket = socket;
        
        // Connection event
        socket.on('connect', function() 
        {
            console.log('Connected to Socket.IO server');
        });
        
        // Disconnection event
        socket.on('disconnect', function() 
        {
            console.log('Disconnected from Socket.IO server');
        });
        
        // Error event
        socket.on('connect_error', function(error) 
        {
            console.error('Socket.IO connection error:', error);
        });
        
        // Update analyzer status indicator
        const statusIndicator = document.getElementById('analyzer-status-indicator');
        
        if (statusIndicator) 
        {
            socket.on('analyzer_status', function(data) 
            {
                if (data.status === 'running') 
                {
                    statusIndicator.innerHTML = '<i class="fas fa-circle text-success me-1"></i> Running';
                } 
                else if (data.status === 'stopped') 
                {
                    statusIndicator.innerHTML = '<i class="fas fa-circle text-danger me-1"></i> Stopped';
                } 
                else if (data.status === 'error') 
                {
                    statusIndicator.innerHTML = '<i class="fas fa-circle text-warning me-1"></i> Error';
                }
            });
        }
        
        // Listen for new incidents if we're on the dashboard
        if (document.getElementById('incidents-table-body')) 
        {
            socket.on('new_incident', function(incident) 
            {
                // This will be handled by dashboard.js
                console.log('New incident received:', incident);
            });
        }
        
        // Listen for statistics updates
        socket.on('statistics_update', function(data) 
        {
            console.log('Statistics update received:', data);
            // Update any live statistics displays
            updateLiveStatistics(data);
        });
    }
    
    /**
     * Update live traffic statistics
     */
    function updateLiveStatistics(data) 
    {
        const statsContainer = document.getElementById('live-traffic-stats');
        if (!statsContainer) return;
        
        // If we have stats array
        if (data.stats && Array.isArray(data.stats)) 
        {
            // Clear "waiting for data" message if it exists
            if (statsContainer.querySelector('.spinner-border')) 
            {
                statsContainer.innerHTML = '';
            }
            
            // Create or update stats table
            let statsTable = statsContainer.querySelector('table');
            
            if (!statsTable) 
            {
                statsTable = document.createElement('table');
                statsTable.className = 'table table-sm table-hover';
                statsTable.innerHTML = `
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Packets</th>
                            <th>Bytes</th>
                            <th>Ports</th>
                        </tr>
                    </thead>
                    <tbody></tbody>
                `;
                statsContainer.appendChild(statsTable);
            }
            
            const tbody = statsTable.querySelector('tbody');
            
            // Update or add rows
            data.stats.forEach(stat => {
                // Look for existing row for this IP
                let row = tbody.querySelector(`tr[data-ip="${stat.ip_address}"]`);
                
                // Create new row if not found
                if (!row) 
                {
                    row = document.createElement('tr');
                    row.setAttribute('data-ip', stat.ip_address);
                    tbody.appendChild(row);
                }
                
                // Update row content
                row.innerHTML = `
                    <td>${stat.ip_address}</td>
                    <td>${formatNumber(stat.packet_count)}</td>
                    <td>${formatBytes(stat.byte_count)}</td>
                    <td>${stat.port_count}</td>
                `;
            });
        }
    }
});
''',

    # Reports page JavaScript
    'reports.js': '''
/**
 * Reports page JavaScript functions
 */
document.addEventListener('DOMContentLoaded', function() {
    // Handle report generation form
    const reportForm = document.getElementById('report-form');
    
    if (reportForm) 
    {
        reportForm.addEventListener('submit', function(event) {
            const submitButton = reportForm.querySelector('button[type="submit"]');
            submitButton.disabled = true;
            submitButton.innerHTML = '<span class="spinner-border spinner-border-sm" role="status" aria-hidden="true"></span> Generating...';
            
            // Form will be submitted normally, this just updates the UI
        });
    }
    
    // Initialize tooltips
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function(tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
});
'''
}

#==============================================================================
# Setup, initialization, and helper functions
#==============================================================================
def setup_directories():
    """Setup directories and initial files."""
    # Create required directories
    os.makedirs('static/reports', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('templates', exist_ok=True)
    
    # Create analyzer config file if it doesn't exist
    if not os.path.exists('analyzer_config.ini'):
        config = configparser.ConfigParser()
        config['General'] = {
            'demo_mode': 'true'
        }
        config['Sniffer'] = {
            'filter': 'tcp port 80 or udp port 53 or tcp port 443',
            'timeout': '3600'
        }
        config['API'] = {
            'virustotal_key': ''
        }
        
        with open('analyzer_config.ini', 'w') as f:
            config.write(f)
    
    # Export static files
    export_static_files()

def render_template(template_name, **context):
    """Use Flask's built-in template rendering."""
    try:
        # Add current year to all templates
        if 'current_year' not in context:
            context['current_year'] = datetime.now().year
        
        # Add analyzer running status
        if 'analyzer_running' not in context and 'get_analyzer' in globals():
            analyzer = get_analyzer()
            context['analyzer_running'] = analyzer.running
        
        # Use Flask's built-in render_template
        return flask_render_template(template_name, **context)
    except Exception as e:
        logger.error(f"Error rendering template {template_name}: {str(e)}")
        return f"Template error: {str(e)}"

def create_admin_user():
    """Create admin user if none exists."""
    with app.app_context():
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            logger.info("Admin user created with credentials admin/admin")

def initialize_database():
    """Initialize database tables and default data."""
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Add default configurations if none exist
        if not AnalyzerConfig.query.first():
            # General configs
            db.session.add(AnalyzerConfig(key='demo_mode', value='true', category='General', description='Run in demo mode with simulated traffic'))
            db.session.add(AnalyzerConfig(key='log_level', value='INFO', category='General', description='Logging level'))
            
            # Sniffer configs
            db.session.add(AnalyzerConfig(key='filter', value='tcp port 80 or udp port 53 or tcp port 443', category='Sniffer', description='Packet capture filter expression'))
            db.session.add(AnalyzerConfig(key='timeout', value='3600', category='Sniffer', description='Capture timeout in seconds (0 for no timeout)'))
            
            # API configs
            db.session.add(AnalyzerConfig(key='virustotal_key', value='', category='API', description='VirusTotal API key for threat intelligence'))
            
            db.session.commit()
            logger.info("Default configurations added")

def init_app():
    """Initialize the application."""
    try:
        # Setup directories and export static files
        setup_directories()
        
        # Initialize database
        initialize_database()
        
        # Create admin user
        create_admin_user()
        
        # Update analyzer config file from database
        with app.app_context():
            update_config_file()
        
        # Start analyzer in demo mode
        analyzer = get_analyzer()
        analyzer.start()
        
        logger.info("Application initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing application: {str(e)}")
        traceback.print_exc()

def handle_error(e):
    """Global error handler for the application."""
    logger.error(f"Application error: {str(e)}")
    return render_template('error.html', error=str(e)), 500
# Add error handler
app.register_error_handler(Exception, handle_error)
# Flask context processors

@app.context_processor
def inject_analyzer_status():
    """Inject analyzer status into all templates."""
    analyzer = get_analyzer()
    return {
        'analyzer_running': analyzer.running
    }
#==============================================================================
# Routes
#==============================================================================
@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
@login_required
@admin_required
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        is_admin = 'is_admin' in request.form
        
        # Check if user exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists', 'danger')
            return render_template('register.html')
        
        # Create user
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            is_admin=is_admin
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('User registered successfully', 'success')
        return redirect(url_for('dashboard'))
    
    return render_template('register.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get recent incidents
    recent_incidents = Incident.query.order_by(Incident.timestamp.desc()).limit(10).all()
    
    # Count incidents by severity
    severity_counts = {}
    for severity in ['high', 'medium', 'low']:
        count = Incident.query.filter_by(severity=severity).count()
        severity_counts[severity] = count
    
    return render_template(
        'dashboard.html',
        recent_incidents=recent_incidents,
        severity_counts=severity_counts,
        analyzer_running=get_analyzer().running
    )

@app.route('/incidents')
@login_required
def incidents():
    # Get filter parameters
    page = request.args.get('page', 1, type=int)
    severity = request.args.get('severity')
    protocol = request.args.get('protocol')
    src_ip = request.args.get('src_ip')
    resolved = request.args.get('resolved')
    
    # Base query
    query = Incident.query
    
    # Apply filters
    if severity:
        query = query.filter_by(severity=severity)
    
    if protocol:
        query = query.filter_by(protocol=protocol)
    
    if src_ip:
        query = query.filter_by(src_ip=src_ip)
    
    if resolved == 'yes':
        query = query.filter_by(resolved=True)
    elif resolved == 'no':
        query = query.filter_by(resolved=False)
    
    # Get all unique protocols for filter dropdown
    protocols = db.session.query(Incident.protocol).distinct().all()
    protocols = [p[0] for p in protocols]
    
    # Paginate results
    incidents = query.order_by(Incident.timestamp.desc()).paginate(page=page, per_page=15)
    
    return render_template(
        'incidents.html',
        incidents=incidents,
        protocols=protocols
    )

@app.route('/incidents/<int:id>', methods=['GET', 'POST'])
@login_required
def incident_detail(id):
    incident = Incident.query.get_or_404(id)
    
    if request.method == 'POST':
        # Update incident
        notes = request.form.get('notes')
        resolved = 'resolved' in request.form
        block_src_ip = 'block_src_ip' in request.form
        
        incident.notes = notes
        incident.resolved = resolved
        
        # Block source IP if requested
        if block_src_ip and current_user.is_admin:
            existing_block = BlockedIP.query.filter_by(ip_address=incident.src_ip).first()
            
            if not existing_block:
                blocked_ip = BlockedIP(
                    ip_address=incident.src_ip,
                    reason=f"Blocked from incident #{incident.id}",
                    added_by=current_user.id
                )
                
                db.session.add(blocked_ip)
                flash(f"IP {incident.src_ip} added to blocklist", 'success')
        
        db.session.commit()
        flash('Incident updated successfully', 'success')
        
        # Reload blocklist in analyzer
        get_analyzer().reload_blocklist()
        
        return redirect(url_for('incident_detail', id=id))
    
    return render_template(
        'incident_detail.html',
        incident=incident,
        Incident=Incident  # Pass model class for related queries in template
    )

@app.route('/config', methods=['GET', 'POST'])
@login_required
@admin_required
def config():
    if request.method == 'POST':
        # Update configurations
        configs = AnalyzerConfig.query.all()
        
        for config in configs:
            new_value = request.form.get(f'config_{config.id}')
            if new_value is not None:
                config.value = new_value
        
        db.session.commit()
        
        # Update config file
        update_config_file()
        
        flash('Configuration updated successfully', 'success')
        return redirect(url_for('config'))
    
    # Group configurations by category
    configurations = {}
    configs = AnalyzerConfig.query.order_by(AnalyzerConfig.category, AnalyzerConfig.key).all()
    
    for config in configs:
        if config.category not in configurations:
            configurations[config.category] = []
        configurations[config.category].append(config)
    
    # Get blocklists
    blocked_ips = BlockedIP.query.filter_by(active=True).all()
    blocked_domains = BlockedDomain.query.filter_by(active=True).all()
    
    return render_template(
        'config.html',
        configurations=configurations,
        blocked_ips=blocked_ips,
        blocked_domains=blocked_domains
    )

@app.route('/block_ip', methods=['POST'])
@login_required
@admin_required
def block_ip():
    ip_address = request.form.get('ip_address')
    reason = request.form.get('reason')
    
    if not ip_address:
        flash('IP address is required', 'danger')
        return redirect(url_for('config'))
    
    # Check if IP is already blocked
    existing = BlockedIP.query.filter_by(ip_address=ip_address).first()
    if existing:
        if not existing.active:
            # Reactivate
            existing.active = True
            existing.reason = reason or existing.reason
            db.session.commit()
            flash(f"IP {ip_address} reactivated in blocklist", 'success')
        else:
            flash(f"IP {ip_address} is already in the blocklist", 'warning')
    else:
        # Add new blocked IP
        blocked_ip = BlockedIP(
            ip_address=ip_address,
            reason=reason,
            added_by=current_user.id
        )
        
        db.session.add(blocked_ip)
        db.session.commit()
        flash(f"IP {ip_address} added to blocklist", 'success')
    
    # Reload blocklist in analyzer
    get_analyzer().reload_blocklist()
    
    return redirect(url_for('config'))

@app.route('/block_domain', methods=['POST'])
@login_required
@admin_required
def block_domain():
    domain = request.form.get('domain')
    reason = request.form.get('reason')
    
    if not domain:
        flash('Domain is required', 'danger')
        return redirect(url_for('config'))
    
    # Check if domain is already blocked
    existing = BlockedDomain.query.filter_by(domain=domain).first()
    if existing:
        if not existing.active:
            # Reactivate
            existing.active = True
            existing.reason = reason or existing.reason
            db.session.commit()
            flash(f"Domain {domain} reactivated in blocklist", 'success')
        else:
            flash(f"Domain {domain} is already in the blocklist", 'warning')
    else:
        # Add new blocked domain
        blocked_domain = BlockedDomain(
            domain=domain,
            reason=reason,
            added_by=current_user.id
        )
        
        db.session.add(blocked_domain)
        db.session.commit()
        flash(f"Domain {domain} added to blocklist", 'success')
    
    # Reload blocklist in analyzer
    get_analyzer().reload_blocklist()
    
    return redirect(url_for('config'))

@app.route('/unblock_ip/<int:id>')
@login_required
@admin_required
def unblock_ip(id):
    blocked_ip = BlockedIP.query.get_or_404(id)
    
    blocked_ip.active = False
    db.session.commit()
    
    flash(f"IP {blocked_ip.ip_address} removed from blocklist", 'success')
    
    # Reload blocklist in analyzer
    get_analyzer().reload_blocklist()
    
    return redirect(url_for('config'))

@app.route('/unblock_domain/<int:id>')
@login_required
@admin_required
def unblock_domain(id):
    blocked_domain = BlockedDomain.query.get_or_404(id)
    
    blocked_domain.active = False
    db.session.commit()
    
    flash(f"Domain {blocked_domain.domain} removed from blocklist", 'success')
    
    # Reload blocklist in analyzer
    get_analyzer().reload_blocklist()
    
    return redirect(url_for('config'))

@app.route('/reports')
@login_required
def reports():
    # Get reports
    reports = Report.query.order_by(Report.generated_at.desc()).all()
    
    return render_template(
        'reports.html',
        reports=reports
    )

@app.route('/generate_report', methods=['POST'])
@login_required
def generate_report():
    report_type = request.form.get('report_type', 'general')
    
    # Generate report
    analyzer = get_analyzer()
    filename = analyzer.generate_report(report_type, current_user.id)
    
    if filename:
        flash('Report generated successfully', 'success')
    else:
        flash('Error generating report', 'danger')
    
    return redirect(url_for('reports'))

@app.route('/download_report/<path:filename>')
@login_required
def download_report(filename):
    return send_from_directory('static/reports', filename, as_attachment=True)

#==============================================================================
# Export static files to disk
#==============================================================================
def export_static_files():
    """Export all JavaScript files and templates to the respective directories."""
    # Export JavaScript files
    for filename, content in STATIC_JS.items():
        with open(f'static/js/{filename}', 'w') as f:
            f.write(content)
    
    # Export templates to the templates directory
    for template_name, content in TEMPLATES.items():
        with open(f'templates/{template_name}', 'w') as f:
            f.write(content)
#==============================================================================
# API Routes
#==============================================================================
@app.route('/api/stats/protocols')
@login_required
def api_protocol_stats():
    """Return protocol distribution statistics."""
    protocols = db.session.query(
        Incident.protocol, db.func.count(Incident.id).label('count')
    ).group_by(Incident.protocol).order_by(db.func.count(Incident.id).desc()).all()
    
    # Format for Chart.js
    labels = [protocol[0] for protocol in protocols]
    data = [protocol[1] for protocol in protocols]
    
    return jsonify({
        'labels': labels,
        'data': data
    })

@app.route('/api/stats/timeline')
@login_required
def api_timeline_stats():
    """Return incident timeline statistics."""
    # Get data for the last 24 hours in 1-hour increments
    now = datetime.now()
    hours = []
    counts = []
    
    for i in range(24):
        start_time = now - timedelta(hours=24-i)
        end_time = now - timedelta(hours=23-i)
        
        count = db.session.query(db.func.count(Incident.id)).filter(
            Incident.timestamp >= start_time,
            Incident.timestamp < end_time
        ).scalar()
        
        hours.append(start_time.strftime('%H:00'))
        counts.append(count)
    
    return jsonify({
        'labels': hours,
        'data': counts
    })

@app.route('/api/stats/severity')
@login_required
def api_severity_stats():
    """Return severity distribution statistics."""
    severities = db.session.query(
        Incident.severity, db.func.count(Incident.id).label('count')
    ).group_by(Incident.severity).all()
    
    # Format for Chart.js
    labels = [severity[0] for severity in severities]
    data = [severity[1] for severity in severities]
    
    return jsonify({
        'labels': labels,
        'data': data
    })

@app.route('/api/recent_incidents')
@login_required
def api_recent_incidents():
    """Return recent incidents as JSON."""
    incidents = Incident.query.order_by(Incident.timestamp.desc()).limit(10).all()
    return jsonify([incident.to_dict() for incident in incidents])

@app.route('/api/export_incidents')
@login_required
def api_export_incidents():
    """Export incidents as CSV or JSON."""
    # Get filter parameters
    severity = request.args.get('severity')
    protocol = request.args.get('protocol')
    src_ip = request.args.get('src_ip')
    resolved_str = request.args.get('resolved')
    export_format = request.args.get('format', 'csv')
    
    # Build query
    query = Incident.query
    
    if severity:
        query = query.filter(Incident.severity == severity)
    
    if protocol:
        query = query.filter(Incident.protocol == protocol)
    
    if src_ip:
        query = query.filter(Incident.src_ip == src_ip)
    
    if resolved_str:
        resolved = resolved_str.lower() == 'yes'
        query = query.filter(Incident.resolved == resolved)
    
    # Get incidents
    incidents = query.order_by(Incident.timestamp.desc()).all()
    
    if export_format == 'json':
        # Return as JSON
        return jsonify([incident.to_dict() for incident in incidents])
    else:
        # Return as CSV
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow(['ID', 'Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Severity', 'Details', 'Resolved'])
        
        # Write data
        for incident in incidents:
            writer.writerow([
                incident.id,
                incident.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                incident.src_ip,
                incident.dst_ip,
                incident.protocol,
                incident.severity,
                incident.details,
                'Yes' if incident.resolved else 'No'
            ])
        
        response = Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment;filename=incidents.csv'}
        )
        
        return response

@app.route('/api/start_analyzer', methods=['POST'])
@login_required
@admin_required
def api_start_analyzer():
    """Start the analyzer."""
    analyzer = get_analyzer()
    analyzer.start()
    return jsonify({
        'status': 'running',
        'message': 'Analyzer started successfully'
    })

@app.route('/api/stop_analyzer', methods=['POST'])
@login_required
@admin_required
def api_stop_analyzer():
    """Stop the analyzer."""
    analyzer = get_analyzer()
    analyzer.stop()
    return jsonify({
        'status': 'stopped',
        'message': 'Analyzer stopped successfully'
    })

@app.route('/api/analyzer_status')
@login_required
def api_analyzer_status():
    """Get analyzer status."""
    analyzer = get_analyzer()
    return jsonify({
        'status': 'running' if analyzer.running else 'stopped',
        'uptime': str(datetime.now() - analyzer.start_time) if analyzer.running else None,
        'processed_packets': analyzer.total_packets_processed
    })

#==============================================================================
# Web Routes
#==============================================================================
def register_routes():
    """Register all route functions if they haven't been registered yet."""
    if 'index' in app.view_functions:
        # Routes already registered, skip to avoid duplicates
        return
    
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return redirect(url_for('login'))
    
    @app.route('/login', methods=['GET', 'POST'])
    def login():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            
            user = User.query.filter_by(username=username).first()
            
            if user and check_password_hash(user.password_hash, password):
                login_user(user)
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid username or password', 'danger')
        
        return render_template('login.html')
    
    @app.route('/register', methods=['GET', 'POST'])
    @login_required
    @admin_required
    def register():
        if request.method == 'POST':
            username = request.form.get('username')
            email = request.form.get('email')
            password = request.form.get('password')
            is_admin = 'is_admin' in request.form
            
            # Check if username or email already exists
            existing_user = User.query.filter(
                (User.username == username) | (User.email == email)
            ).first()
            
            if existing_user:
                flash('Username or email already exists', 'danger')
                return redirect(url_for('register'))
            
            # Create new user
            new_user = User(
                username=username,
                email=email,
                password_hash=generate_password_hash(password),
                is_admin=is_admin
            )
            
            db.session.add(new_user)
            db.session.commit()
            
            flash(f'User {username} created successfully', 'success')
            return redirect(url_for('dashboard'))
        
        return render_template('register.html')
    
    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('login'))
    
    @app.route('/dashboard')
    @login_required
    def dashboard():
        # Get recent incidents
        recent_incidents = Incident.query.order_by(Incident.timestamp.desc()).limit(10).all()
        
        # Get severity counts
        high_count = Incident.query.filter_by(severity='high').count()
        medium_count = Incident.query.filter_by(severity='medium').count()
        low_count = Incident.query.filter_by(severity='low').count()
        
        severity_counts = {
            'high': high_count,
            'medium': medium_count,
            'low': low_count
        }
        
        return render_template(
            'dashboard.html',
            recent_incidents=recent_incidents,
            severity_counts=severity_counts
        )
    
    @app.route('/incidents')
    @login_required
    def incidents():
        # Get filter parameters
        page = request.args.get('page', 1, type=int)
        severity = request.args.get('severity')
        protocol = request.args.get('protocol')
        src_ip = request.args.get('src_ip')
        resolved_str = request.args.get('resolved')
        
        # Build query
        query = Incident.query
        
        if severity:
            query = query.filter(Incident.severity == severity)
        
        if protocol:
            query = query.filter(Incident.protocol == protocol)
        
        if src_ip:
            query = query.filter(Incident.src_ip == src_ip)
        
        if resolved_str:
            resolved = resolved_str.lower() == 'yes'
            query = query.filter(Incident.resolved == resolved)
        
        # Get paginated results
        incidents = query.order_by(Incident.timestamp.desc()).paginate(page=page, per_page=20)
        
        # Get unique protocols for filter dropdown
        protocols = db.session.query(Incident.protocol).distinct().all()
        protocols = [p[0] for p in protocols]
        
        return render_template(
            'incidents.html',
            incidents=incidents,
            protocols=protocols
        )
    
    @app.route('/incidents/<int:id>', methods=['GET', 'POST'])
    @login_required
    def incident_detail(id):
        incident = Incident.query.get_or_404(id)
        
        if request.method == 'POST':
            # Update incident
            incident.notes = request.form.get('notes')
            incident.resolved = 'resolved' in request.form
            
            # Check if admin wants to block the source IP
            if current_user.is_admin and 'block_src_ip' in request.form:
                # Check if IP is already blocked
                existing_block = BlockedIP.query.filter_by(ip_address=incident.src_ip).first()
                
                if not existing_block:
                    blocked_ip = BlockedIP(
                        ip_address=incident.src_ip,
                        reason=f"Blocked due to incident #{incident.id}",
                        added_by=current_user.id
                    )
                    db.session.add(blocked_ip)
                    
                    flash(f"IP address {incident.src_ip} has been blocked", 'success')
            
            db.session.commit()
            
            # Reload blocklist in analyzer
            analyzer = get_analyzer()
            analyzer.reload_blocklist()
            
            flash('Incident updated successfully', 'success')
            return redirect(url_for('incident_detail', id=id))
        
        # Get related incidents
        related_incidents = Incident.query.filter(
            (Incident.src_ip == incident.src_ip) | (Incident.dst_ip == incident.dst_ip),
            Incident.id != incident.id
        ).order_by(Incident.timestamp.desc()).limit(5).all()
        
        return render_template(
            'incident_detail.html',
            incident=incident,
            related_incidents=related_incidents
        )
    
    @app.route('/config', methods=['GET', 'POST'])
    @login_required
    @admin_required
    def config():
        if request.method == 'POST':
            # Process form data
            for key, value in request.form.items():
                if key.startswith('config_'):
                    config_id = int(key.split('_')[1])
                    config_item = AnalyzerConfig.query.get(config_id)
                    
                    if config_item:
                        config_item.value = value
            
            db.session.commit()
            
            # Update config file
            update_config_file()
            
            flash('Configuration updated successfully', 'success')
            return redirect(url_for('config'))
        
        # Get configuration items grouped by category
        configs = AnalyzerConfig.query.order_by(AnalyzerConfig.category, AnalyzerConfig.key).all()
        
        # Group by category
        categories = {}
        for config in configs:
            if config.category not in categories:
                categories[config.category] = []
            categories[config.category].append(config)
        
        # Get blocklists
        blocked_ips = BlockedIP.query.filter_by(active=True).all()
        blocked_domains = BlockedDomain.query.filter_by(active=True).all()
        
        return render_template(
            'config.html',
            categories=categories,
            blocked_ips=blocked_ips,
            blocked_domains=blocked_domains
        )
    
    @app.route('/block_ip', methods=['POST'])
    @login_required
    @admin_required
    def block_ip():
        ip_address = request.form.get('ip_address')
        reason = request.form.get('reason')
        
        if not ip_address:
            flash('IP address is required', 'danger')
            return redirect(url_for('config'))
        
        # Check if already exists
        existing = BlockedIP.query.filter_by(ip_address=ip_address).first()
        
        if existing:
            if not existing.active:
                # Reactivate
                existing.active = True
                existing.reason = reason
                existing.added_at = datetime.utcnow()
                existing.added_by = current_user.id
                
                db.session.commit()
                flash(f'IP address {ip_address} has been reactivated in the blocklist', 'success')
            else:
                flash(f'IP address {ip_address} is already in the blocklist', 'warning')
        else:
            # Add new
            blocked_ip = BlockedIP(
                ip_address=ip_address,
                reason=reason,
                added_by=current_user.id
            )
            
            db.session.add(blocked_ip)
            db.session.commit()
            
            flash(f'IP address {ip_address} has been added to the blocklist', 'success')
        
        # Reload blocklist in analyzer
        analyzer = get_analyzer()
        analyzer.reload_blocklist()
        
        return redirect(url_for('config'))
    
    @app.route('/block_domain', methods=['POST'])
    @login_required
    @admin_required
    def block_domain():
        domain = request.form.get('domain')
        reason = request.form.get('reason')
        
        if not domain:
            flash('Domain is required', 'danger')
            return redirect(url_for('config'))
        
        # Check if already exists
        existing = BlockedDomain.query.filter_by(domain=domain).first()
        
        if existing:
            if not existing.active:
                # Reactivate
                existing.active = True
                existing.reason = reason
                existing.added_at = datetime.utcnow()
                existing.added_by = current_user.id
                
                db.session.commit()
                flash(f'Domain {domain} has been reactivated in the blocklist', 'success')
            else:
                flash(f'Domain {domain} is already in the blocklist', 'warning')
        else:
            # Add new
            blocked_domain = BlockedDomain(
                domain=domain,
                reason=reason,
                added_by=current_user.id
            )
            
            db.session.add(blocked_domain)
            db.session.commit()
            
            flash(f'Domain {domain} has been added to the blocklist', 'success')
        
        # Reload blocklist in analyzer
        analyzer = get_analyzer()
        analyzer.reload_blocklist()
        
        return redirect(url_for('config'))
    
    @app.route('/unblock_ip/<int:id>')
    @login_required
    @admin_required
    def unblock_ip(id):
        blocked_ip = BlockedIP.query.get_or_404(id)
        
        blocked_ip.active = False
        db.session.commit()
        
        # Reload blocklist in analyzer
        analyzer = get_analyzer()
        analyzer.reload_blocklist()
        
        flash(f'IP address {blocked_ip.ip_address} has been removed from the blocklist', 'success')
        return redirect(url_for('config'))
    
    @app.route('/unblock_domain/<int:id>')
    @login_required
    @admin_required
    def unblock_domain(id):
        blocked_domain = BlockedDomain.query.get_or_404(id)
        
        blocked_domain.active = False
        db.session.commit()
        
        # Reload blocklist in analyzer
        analyzer = get_analyzer()
        analyzer.reload_blocklist()
        
        flash(f'Domain {blocked_domain.domain} has been removed from the blocklist', 'success')
        return redirect(url_for('config'))
    @app.route('/reports')
    @login_required
    def reports():
        # Get all reports
        reports = Report.query.order_by(Report.generated_at.desc()).all()
        
        return render_template('reports.html', reports=reports)
    @app.route('/reports/generate', methods=['POST'])
    @login_required
    def generate_report():
        report_type = request.form.get('report_type', 'general')
        
        analyzer = get_analyzer()
        filename = analyzer.generate_report(report_type, current_user.id)
        
        if filename:
            flash('Report generated successfully', 'success')
        else:
            flash('Error generating report', 'danger')
        
        return redirect(url_for('reports'))
    @app.route('/reports/download/<path:filename>')
    @login_required
    def download_report(filename):
        return send_from_directory('static/reports', filename, as_attachment=True)
    # API routes
    @app.route('/api/stats/protocols')
    @login_required
    def api_protocol_stats():
        """Return protocol distribution statistics."""
        protocols = db.session.query(
            Incident.protocol, db.func.count(Incident.id).label('count')
        ).group_by(Incident.protocol).order_by(db.func.count(Incident.id).desc()).all()
        
        # Format for Chart.js
        labels = [protocol[0] for protocol in protocols]
        data = [protocol[1] for protocol in protocols]
        
        return jsonify({
            'labels': labels,
            'data': data
        })
    @app.route('/api/stats/timeline')
    @login_required
    def api_timeline_stats():
        """Return incident timeline statistics."""
        # Get data for the last 24 hours in 1-hour increments
        now = datetime.now()
        hours = []
        counts = []
        
        for i in range(24):
            start_time = now - timedelta(hours=24-i)
            end_time = now - timedelta(hours=23-i)
            
            count = db.session.query(db.func.count(Incident.id)).filter(
                Incident.timestamp >= start_time,
                Incident.timestamp < end_time
            ).scalar()
            
            hours.append(start_time.strftime('%H:00'))
            counts.append(count)
        
        return jsonify({
            'labels': hours,
            'data': counts
        })
    @app.route('/api/stats/severity')
    @login_required
    def api_severity_stats():
        """Return severity distribution statistics."""
        severities = db.session.query(
            Incident.severity, db.func.count(Incident.id).label('count')
        ).group_by(Incident.severity).all()
        
        # Format for Chart.js
        labels = [severity[0] for severity in severities]
        data = [severity[1] for severity in severities]
        
        return jsonify({
            'labels': labels,
            'data': data
        })
    @app.route('/api/recent_incidents')
    @login_required
    def api_recent_incidents():
        """Return recent incidents as JSON."""
        incidents = Incident.query.order_by(Incident.timestamp.desc()).limit(10).all()
        return jsonify([incident.to_dict() for incident in incidents])
    @app.route('/api/export_incidents')
    @login_required
    def api_export_incidents():
        """Export incidents as CSV or JSON."""
        # Get filter parameters
        severity = request.args.get('severity')
        protocol = request.args.get('protocol')
        src_ip = request.args.get('src_ip')
        resolved_str = request.args.get('resolved')
        export_format = request.args.get('format', 'csv')
        
        # Build query
        query = Incident.query
        
        if severity:
            query = query.filter(Incident.severity == severity)
        
        if protocol:
            query = query.filter(Incident.protocol == protocol)
        
        if src_ip:
            query = query.filter(Incident.src_ip == src_ip)
        
        if resolved_str:
            resolved = resolved_str.lower() == 'yes'
            query = query.filter(Incident.resolved == resolved)
        
        # Get incidents
        incidents = query.order_by(Incident.timestamp.desc()).all()
        
        if export_format == 'json':
            # Return as JSON
            return jsonify([incident.to_dict() for incident in incidents])
        else:
            # Return as CSV
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            writer.writerow(['ID', 'Timestamp', 'Source IP', 'Destination IP', 'Protocol', 'Severity', 'Details', 'Resolved'])
            
            # Write data
            for incident in incidents:
                writer.writerow([
                    incident.id,
                    incident.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
                    incident.src_ip,
                    incident.dst_ip,
                    incident.protocol,
                    incident.severity,
                    incident.details,
                    'Yes' if incident.resolved else 'No'
                ])
            
            response = Response(
                output.getvalue(),
                mimetype='text/csv',
                headers={'Content-Disposition': 'attachment;filename=incidents.csv'}
            )
            
            return response
    @app.route('/api/start_analyzer', methods=['POST'])
    @login_required
    @admin_required
    def api_start_analyzer():
        """Start the analyzer."""
        analyzer = get_analyzer()
        analyzer.start()
        return jsonify({
            'status': 'running',
            'message': 'Analyzer started successfully'
        })
    @app.route('/api/stop_analyzer', methods=['POST'])
    @login_required
    @admin_required
    def api_stop_analyzer():
        """Stop the analyzer."""
        analyzer = get_analyzer()
        analyzer.stop()
        return jsonify({
            'status': 'stopped',
            'message': 'Analyzer stopped successfully'
        })
    @app.route('/api/analyzer_status')
    @login_required
    def api_analyzer_status():
        """Get analyzer status."""
        analyzer = get_analyzer()
        return jsonify({
            'status': 'running' if analyzer.running else 'stopped',
            'uptime': str(datetime.now() - analyzer.start_time) if analyzer.running else None,
            'processed_packets': analyzer.total_packets_processed
        })
    # Socket.IO Events
    @socketio.on('connect')
    def handle_connect():
        # Emit analyzer status on connect
        analyzer = get_analyzer()
        emit('analyzer_status', {
            'status': 'running' if analyzer.running else 'stopped'
        })
    @socketio.on('request_incidents')
    def handle_request_incidents():
        # Send recent incidents to client
        incidents = Incident.query.order_by(Incident.timestamp.desc()).limit(10).all()
        emit('incidents_update', [incident.to_dict() for incident in incidents])

#==============================================================================
# Main application initialization
#==============================================================================
def init_app():
    """Initialize the application."""
    try:
        # Setup directories and export static files
        setup_directories()
        
        # Register all routes
        register_routes()
        
        # Initialize database
        initialize_database()
        
        # Create admin user
        create_admin_user()
        
        # Update analyzer config file from database
        with app.app_context():
            update_config_file()
        
        # Start analyzer in demo mode
        analyzer = get_analyzer()
        analyzer.start()
        
        logger.info("Application initialized successfully")
    except Exception as e:
        logger.error(f"Error initializing application: {str(e)}")
        traceback.print_exc()

def create_admin_user():
    """Create admin user if none exists."""
    with app.app_context():
        if not User.query.filter_by(username='admin').first():
            admin = User(
                username='admin',
                email='admin@example.com',
                password_hash=generate_password_hash('admin'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
            logger.info("Admin user created with credentials admin/admin")

def initialize_database():
    """Initialize database tables and default data."""
    with app.app_context():
        # Create all tables
        db.create_all()
        
        # Add default configurations if none exist
        if not AnalyzerConfig.query.first():
            # General configs
            db.session.add(AnalyzerConfig(key='demo_mode', value='true', category='General', description='Run in demo mode with simulated traffic'))
            db.session.add(AnalyzerConfig(key='log_level', value='INFO', category='General', description='Logging level'))
            
            # Sniffer configs
            db.session.add(AnalyzerConfig(key='filter', value='tcp port 80 or udp port 53 or tcp port 443', category='Sniffer', description='Packet capture filter expression'))
            db.session.add(AnalyzerConfig(key='timeout', value='3600', category='Sniffer', description='Capture timeout in seconds (0 for no timeout)'))
            
            # API configs
            db.session.add(AnalyzerConfig(key='virustotal_key', value='', category='API', description='VirusTotal API key for threat intelligence'))
            
            db.session.commit()
            logger.info("Default configurations added")

def handle_error(e):
    """Global error handler for the application."""
    logger.error(f"Application error: {str(e)}")
    return render_template('error.html', error=str(e)), 500
# Add error handler
app.register_error_handler(Exception, handle_error)

# Flask context processors
@app.context_processor
def inject_analyzer_status():
    """Inject analyzer status into all templates."""
    analyzer = get_analyzer()
    return {
        'analyzer_running': analyzer.running
    }

#==============================================================================
# Main Entry Point
#==============================================================================
if __name__ == '__main__':
    # Initialize the application
    init_app()
    
    # Run the Flask application with Socket.IO
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
else:
    # WSGI entry point - initialize the application
    init_app()