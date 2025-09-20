#!/usr/bin/env python3
# -------------------------------------------------------------------
# Enhanced Homograph Attack Demonstrator (Educational Tool)
# by basty-devel
# PURPOSE:
# This script is for educational use ONLY. It demonstrates how
# Internationalized Domain Name (IDN) homograph attacks are constructed
# by substituting Latin characters with visually similar non-Latin ones.
#
# ENHANCEMENTS:
# 1. Expanded character substitution map with Cyrillic and Greek homoglyphs
# 2. PyQt5 GUI for interactive usage
# 3. WHOIS lookup functionality to check domain registration status
# 4. Online domain availability check via socket connection
# 5. Detailed results display showing substitutions and domain status
#
# By understanding the mechanics, you can better defend against them.
# -------------------------------------------------------------------
import sys
import itertools
import socket
import whois
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTextEdit, QCheckBox, QGroupBox, QProgressBar,
                             QMessageBox, QTableWidget, QTableWidgetItem,
                             QHeaderView, QSplitter)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QColor

# Expanded map of Latin to visually similar non-Latin characters
# Includes Cyrillic and Greek homoglyphs that are visually similar
HOMOGLYPH_MAP = {
    # Latin: (Cyrillic, Greek)
    'a': ('а', 'α'),      # Cyrillic small a, Greek alpha
    'b': ('ь', ''),       # Cyrillic soft sign (visual similarity in some fonts)
    'c': ('с', ''),       # Cyrillic small es
    'd': ('ԁ', ''),       # Cyrillic small komi de
    'e': ('е', 'е'),      # Cyrillic small ie, Greek epsilon (not perfect but sometimes used)
    'f': ('ƒ', ''),       # Latin small f with hook (cross-script)
    'g': ('ɡ', ''),       # Latin small script g
    'h': ('һ', ''),       # Cyrillic small shha
    'i': ('і', 'і'),      # Cyrillic small byelorussian-ukrainian i
    'j': ('ј', ''),       # Cyrillic small je
    'k': ('к', ''),       # Cyrillic small ka
    'l': ('Ӏ', ''),       # Cyrillic small palochka
    'm': ('м', ''),       # Cyrillic small em
    'n': ('п', ''),       # Cyrillic small pe (caution: resembles n in some fonts)
    'o': ('о', 'ο'),      # Cyrillic small o, Greek omicron
    'p': ('р', ''),       # Cyrillic small er
    'q': ('ԛ', ''),       # Cyrillic small qa
    'r': ('г', ''),       # Cyrillic small ghe (resembles r)
    's': ('ѕ', ''),       # Cyrillic small dze
    't': ('т', ''),       # Cyrillic small te
    'u': ('υ', ''),       # Greek upsilon (resembles u)
    'v': ('ν', ''),       # Greek nu (resembles v)
    'w': ('ѡ', ''),       # Cyrillic small omega
    'x': ('х', 'χ'),      # Cyrillic small ha, Greek chi
    'y': ('у', 'γ'),      # Cyrillic small u, Greek gamma
    'z': ('з', ''),       # Cyrillic small ze (resembles z in some fonts)
}

def generate_homographs(domain, use_cyrillic=True, use_greek=True, max_combinations=50):
    """
    Generates homograph variations of a domain name using non-Latin characters.

    Args:
        domain (str): The input domain name (e.g., "google.com").
        use_cyrillic (bool): Whether to use Cyrillic character substitutions.
        use_greek (bool): Whether to use Greek character substitutions.
        max_combinations (int): Maximum number of combinations to generate.

    Returns:
        A list of tuples, where each tuple contains:
        (generated_homograph_domain, list_of_replacements, script_type)
    """
    if '.' not in domain:
        return []

    base_name = domain.split('.')[0].lower()
    tld = '.' + '.'.join(domain.split('.')[1:])
    
    # Find the indices of characters that can be replaced
    replaceable_indices = []
    replacement_options = {}  # Index: list of possible replacements
    
    for i, char in enumerate(base_name):
        if char in HOMOGLYPH_MAP:
            scripts = []
            if use_cyrillic and HOMOGLYPH_MAP[char][0]:
                scripts.append(('Cyrillic', HOMOGLYPH_MAP[char][0]))
            if use_greek and HOMOGLYPH_MAP[char][1]:
                scripts.append(('Greek', HOMOGLYPH_MAP[char][1]))
                
            if scripts:
                replaceable_indices.append(i)
                replacement_options[i] = scripts
    
    if not replaceable_indices:
        return []

    generated_domains = []
    combination_count = 0

    # Generate combinations, limiting to max_combinations
    for r in range(1, len(replaceable_indices) + 1):
        for indices_to_replace in itertools.combinations(replaceable_indices, r):
            if combination_count >= max_combinations:
                break
                
            # For each index to replace, we need to choose one script
            # Generate all script combinations for these indices
            script_choices = [replacement_options[idx] for idx in indices_to_replace]
            for script_combination in itertools.product(*script_choices):
                if combination_count >= max_combinations:
                    break
                    
                new_domain_list = list(base_name)
                replacements = []
                
                for idx, (script, char_replacement) in zip(indices_to_replace, script_combination):
                    original_char = base_name[idx]
                    new_domain_list[idx] = char_replacement
                    replacements.append(f"'{original_char}'→'{char_replacement}'({script})")
                
                homograph_domain = "".join(new_domain_list) + tld
                generated_domains.append((homograph_domain, replacements, script_combination[0][0]))
                combination_count += 1
                
    return generated_domains

def check_domain_online(domain):
    """
    Check if a domain is online by attempting to resolve it.
    
    Args:
        domain (str): Domain name to check
        
    Returns:
        bool: True if domain resolves, False otherwise
    """
    try:
        socket.gethostbyname(domain)
        return True
    except socket.gaierror:
        return False

def get_whois_info(domain):
    """
    Perform WHOIS lookup for a domain.
    
    Args:
        domain (str): Domain name to lookup
        
    Returns:
        dict or None: WHOIS information if available, None otherwise
    """
    try:
        return whois.whois(domain)
    except Exception:
        return None

class WorkerThread(QThread):
    """
    Worker thread for performing domain checks without freezing the GUI.
    """
    progress_updated = pyqtSignal(int, int, str)  # current, total, domain
    result_ready = pyqtSignal(list)  # list of result dictionaries
    finished = pyqtSignal()

    def __init__(self, domain, use_cyrillic, use_greek, check_whois, check_online, max_combinations):
        super().__init__()
        self.domain = domain
        self.use_cyrillic = use_cyrillic
        self.use_greek = use_greek
        self.check_whois = check_whois
        self.check_online = check_online
        self.max_combinations = max_combinations
        self.results = []

    def run(self):
        # Generate homograph variants
        homographs = generate_homographs(
            self.domain, self.use_cyrillic, self.use_greek, self.max_combinations
        )
        
        total = len(homographs)
        self.results = []
        
        for i, (homograph, replacements, script) in enumerate(homographs):
            # Update progress
            self.progress_updated.emit(i + 1, total, homograph)
            
            # Get Punycode representation
            try:
                punycode = homograph.encode('idna').decode('ascii')
            except UnicodeError:
                punycode = "Encoding error"
            
            # Check if domain is online
            is_online = check_domain_online(homograph) if self.check_online else None
            
            # Get WHOIS information
            whois_info = None
            is_registered = None
            if self.check_whois:
                whois_info = get_whois_info(homograph)
                if whois_info:
                    is_registered = True
                else:
                    is_registered = False
            
            result = {
                'domain': homograph,
                'punycode': punycode,
                'replacements': replacements,
                'script': script,
                'online': is_online,
                'registered': is_registered,
                'whois_info': whois_info
            }
            
            self.results.append(result)
        
        self.result_ready.emit(self.results)
        self.finished.emit()

class HomographGUI(QMainWindow):
    """
    Main GUI window for the Homograph Attack Demonstrator.
    """
    def __init__(self):
        super().__init__()
        self.initUI()
        
    def initUI(self):
        self.setWindowTitle('IDN Homograph Attack Demonstrator')
        self.setGeometry(100, 100, 1000, 700)
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Input section
        input_group = QGroupBox("Domain Input")
        input_layout = QVBoxLayout()
        
        domain_layout = QHBoxLayout()
        domain_layout.addWidget(QLabel("Domain to analyze:"))
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("example.com")
        domain_layout.addWidget(self.domain_input)
        
        self.analyze_btn = QPushButton("Analyze")
        self.analyze_btn.clicked.connect(self.start_analysis)
        domain_layout.addWidget(self.analyze_btn)
        input_layout.addLayout(domain_layout)
        
        # Options
        options_layout = QHBoxLayout()
        self.cyrillic_check = QCheckBox("Use Cyrillic characters")
        self.cyrillic_check.setChecked(True)
        options_layout.addWidget(self.cyrillic_check)
        
        self.greek_check = QCheckBox("Use Greek characters")
        self.greek_check.setChecked(True)
        options_layout.addWidget(self.greek_check)
        
        self.whois_check = QCheckBox("Perform WHOIS lookup")
        self.whois_check.setChecked(True)
        options_layout.addWidget(self.whois_check)
        
        self.online_check = QCheckBox("Check if domain is online")
        self.online_check.setChecked(True)
        options_layout.addWidget(self.online_check)
        input_layout.addLayout(options_layout)
        
        input_group.setLayout(input_layout)
        layout.addWidget(input_group)
        
        # Progress section
        progress_group = QGroupBox("Progress")
        progress_layout = QVBoxLayout()
        
        self.progress_bar = QProgressBar()
        self.progress_label = QLabel("Ready")
        progress_layout.addWidget(self.progress_label)
        progress_layout.addWidget(self.progress_bar)
        
        progress_group.setLayout(progress_layout)
        layout.addWidget(progress_group)
        
        # Results section
        results_group = QGroupBox("Results")
        results_layout = QVBoxLayout()
        
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            "Homograph Domain", "Punycode", "Script", "Replacements", 
            "Online", "Registered"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.results_table.doubleClicked.connect(self.show_details)
        results_layout.addWidget(self.results_table)
        
        results_group.setLayout(results_layout)
        layout.addWidget(results_group)
        
        # Status bar
        self.statusBar().showMessage('Ready')
        
        self.worker_thread = None
        
    def start_analysis(self):
        domain = self.domain_input.text().strip()
        if not domain:
            QMessageBox.warning(self, "Input Error", "Please enter a domain name to analyze.")
            return
            
        if '.' not in domain:
            QMessageBox.warning(self, "Input Error", "Please enter a valid domain name (e.g., example.com).")
            return
            
        # Disable button during analysis
        self.analyze_btn.setEnabled(False)
        self.statusBar().showMessage('Analyzing...')
        
        # Create and start worker thread
        self.worker_thread = WorkerThread(
            domain,
            self.cyrillic_check.isChecked(),
            self.greek_check.isChecked(),
            self.whois_check.isChecked(),
            self.online_check.isChecked(),
            max_combinations=100  # Limit to prevent UI freeze
        )
        
        self.worker_thread.progress_updated.connect(self.update_progress)
        self.worker_thread.result_ready.connect(self.display_results)
        self.worker_thread.finished.connect(self.analysis_finished)
        self.worker_thread.start()
        
    def update_progress(self, current, total, domain):
        self.progress_bar.setMaximum(total)
        self.progress_bar.setValue(current)
        self.progress_label.setText(f"Processing: {domain} ({current}/{total})")
        
    def display_results(self, results):
        self.results_table.setRowCount(len(results))
        
        for row, result in enumerate(results):
            self.results_table.setItem(row, 0, QTableWidgetItem(result['domain']))
            self.results_table.setItem(row, 1, QTableWidgetItem(result['punycode']))
            self.results_table.setItem(row, 2, QTableWidgetItem(result['script']))
            self.results_table.setItem(row, 3, QTableWidgetItem(', '.join(result['replacements'])))
            
            # Online status
            online_item = QTableWidgetItem()
            if result['online'] is True:
                online_item.setText("Yes")
                online_item.setBackground(QColor(255, 200, 200))  # Light red
            elif result['online'] is False:
                online_item.setText("No")
                online_item.setBackground(QColor(200, 255, 200))  # Light green
            else:
                online_item.setText("Not checked")
            self.results_table.setItem(row, 4, online_item)
            
            # Registration status
            reg_item = QTableWidgetItem()
            if result['registered'] is True:
                reg_item.setText("Yes")
                reg_item.setBackground(QColor(255, 200, 200))  # Light red
            elif result['registered'] is False:
                reg_item.setText("No")
                reg_item.setBackground(QColor(200, 255, 200))  # Light green
            else:
                reg_item.setText("Not checked")
            self.results_table.setItem(row, 5, reg_item)
            
            # Store full result data
            self.results_table.setItem(row, 0, QTableWidgetItem(result['domain']))
            self.results_table.item(row, 0).setData(Qt.UserRole, result)
        
    def show_details(self):
        current_row = self.results_table.currentRow()
        if current_row < 0:
            return
            
        item = self.results_table.item(current_row, 0)
        result = item.data(Qt.UserRole)
        
        details = f"""
        <h3>Domain Details</h3>
        <b>Homograph Domain:</b> {result['domain']}<br>
        <b>Punycode:</b> {result['punycode']}<br>
        <b>Script:</b> {result['script']}<br>
        <b>Replacements:</b> {', '.join(result['replacements'])}<br>
        <b>Online:</b> {('Yes' if result['online'] else 'No') if result['online'] is not None else 'Not checked'}<br>
        <b>Registered:</b> {('Yes' if result['registered'] else 'No') if result['registered'] is not None else 'Not checked'}<br>
        """
        
        if result['whois_info']:
            details += "<h3>WHOIS Information</h3>"
            whois_info = result['whois_info']
            
            if hasattr(whois_info, 'domain_name'):
                details += f"<b>Domain Name:</b> {whois_info.domain_name}<br>"
            if hasattr(whois_info, 'registrar'):
                details += f"<b>Registrar:</b> {whois_info.registrar}<br>"
            if hasattr(whois_info, 'creation_date'):
                # Handle possible list of dates
                creation_date = whois_info.creation_date
                if isinstance(creation_date, list) and len(creation_date) > 0:
                    creation_date = creation_date[0]
                if isinstance(creation_date, datetime):
                    creation_date = creation_date.strftime("%Y-%m-%d")
                details += f"<b>Creation Date:</b> {creation_date}<br>"
            if hasattr(whois_info, 'expiration_date'):
                # Handle possible list of dates
                exp_date = whois_info.expiration_date
                if isinstance(exp_date, list) and len(exp_date) > 0:
                    exp_date = exp_date[0]
                if isinstance(exp_date, datetime):
                    exp_date = exp_date.strftime("%Y-%m-%d")
                details += f"<b>Expiration Date:</b> {exp_date}<br>"
            if hasattr(whois_info, 'name_servers'):
                details += f"<b>Name Servers:</b> {', '.join(whois_info.name_servers) if isinstance(whois_info.name_servers, list) else whois_info.name_servers}<br>"
        
        msg = QMessageBox()
        msg.setWindowTitle("Domain Details")
        msg.setTextFormat(Qt.RichText)
        msg.setText(details)
        msg.exec_()
        
    def analysis_finished(self):
        self.analyze_btn.setEnabled(True)
        self.statusBar().showMessage('Analysis completed')
        self.progress_label.setText("Analysis completed")

def main():
    """
    Main function to run the application.
    """
    # If command line argument is provided, use CLI mode
    if len(sys.argv) > 1:
        domain_to_check = sys.argv[1]
        print(f"Analyzing domain: {domain_to_check}")
        
        homographs = generate_homographs(domain_to_check)
        
        if not homographs:
            print("No homograph variants could be generated for this domain.")
            return
            
        print(f"\nGenerated {len(homographs)} homograph variants:")
        print("-" * 80)
        
        for i, (domain, replacements, script) in enumerate(homographs):
            try:
                punycode = domain.encode('idna').decode('ascii')
            except UnicodeError:
                punycode = "Encoding error"
                
            print(f"{i+1}. {domain} (Punycode: {punycode})")
            print(f"   Script: {script}, Replacements: {', '.join(replacements)}")
            
            # Check if domain is online
            online = check_domain_online(domain)
            print(f"   Online: {'Yes' if online else 'No'}")
            
            # Perform WHOIS lookup
            whois_info = get_whois_info(domain)
            print(f"   Registered: {'Yes' if whois_info else 'No'}")
            
            if whois_info:
                if hasattr(whois_info, 'registrar'):
                    print(f"   Registrar: {whois_info.registrar}")
                if hasattr(whois_info, 'creation_date'):
                    print(f"   Creation Date: {whois_info.creation_date}")
            
            print("-" * 80)
    else:
        # Launch GUI if no command line arguments
        app = QApplication(sys.argv)
        gui = HomographGUI()
        gui.show()
        sys.exit(app.exec_())

if __name__ == "__main__":
    main()
