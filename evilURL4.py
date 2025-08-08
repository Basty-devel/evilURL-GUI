#!/usr/bin/env python3
#------------------------------------------------------
#      BY: UNDEADSEC from BRAZIL :) AND Basty-devel from Germany
#      YouTube: https://www.youtube.com/c/UndeadSec
#      Github: https://github.com/UndeadSec/EvilURL
#      Version: 4.0 - EvilURL4 (Classroom Edition)
#------------------------------------------------------
import os
import sys
import itertools
import socket
import threading
import time
try:
    import whois
except ImportError:
    print("The 'whois' module is not installed. Please run 'pip install python-whois'.")
    sys.exit(1)
from datetime import datetime
from urllib.parse import urlparse

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QLineEdit, QPushButton, QTextEdit, QLabel, QCheckBox, QFileDialog,
    QGroupBox, QMessageBox, QProgressBar, QStatusBar
)
from PyQt5.QtCore import Qt, pyqtSignal, QThread
from PyQt5.QtGui import QFont, QTextCursor, QColor, QTextCharFormat, QPalette

# ANSI color codes
RED, WHITE, GREEN, END, YELLOW, CYAN = (
    '\033[91m', '\33[97m', '\033[1;32m', '\033[0m', '\33[93m', '\033[96m'
)

# Extended Cyrillic characters similar to Latin letters
EVIL_MAP = {
    'a': ['\u0430', '\u04D0', '\u0101'],  # а, Ӑ, ā
    'b': ['\u042C', '\u13CF'],            # ь, Ꮟ
    'c': ['\u0441', '\u03F2', '\u03C2'],  # с, ϲ, ς
    'd': ['\u0501', '\u217E'],            # ԁ, ⅾ
    'e': ['\u0435', '\u04BD', '\u0113'],  # е, ӽ, ē
    'f': ['\u04FB', '\u0584'],            # ӻ, ք
    'g': ['\u0581', '\u0260'],            # ց, ɠ
    'h': ['\u04BB', '\u13C2'],            # һ, Ꮒ
    'i': ['\u0456', '\u037F', '\u0268'],  # і, Ϳ, ɨ
    'j': ['\u0458', '\u037F'],            # ј, Ϳ
    'k': ['\u13E6', '\u04C3'],            # Ꮶ, Ӄ
    'l': ['\u04CF', '\u217C'],            # ӏ, ⅼ
    'm': ['\u13B8', '\u217F'],            # Ꮈ, ⅿ
    'n': ['\u0578', '\u057C'],            # ն, ռ
    'o': ['\u043E', '\u03BF', '\u0585'],  # о, ο, օ
    'p': ['\u0440', '\u03F1'],            # р, ϱ
    'q': ['\u051B', '\u0563'],            # ԛ, գ
    'r': ['\u1EA1', '\u0433'],            # ạ, г
    's': ['\u0455', '\u03C2'],            # ѕ, ς
    't': ['\u1E6D', '\u0442'],            # ṭ, т
    'u': ['\u057D', '\u057E'],            # մ, մ
    'v': ['\u1E7F', '\u0475'],            # ṿ, ѵ
    'w': ['\u051D', '\u0561'],            # ԝ, ա
    'x': ['\u0445', '\u04B3'],            # х, ҳ
    'y': ['\u0443', '\u04AF'],            # у, ү
    'z': ['\u1E93', '\u0225'],            # ẓ, ȥ
}

UNICODE_DESCRIPTIONS = {
    '\u0430': 'Cyrillic Small Letter A',
    '\u0441': 'Cyrillic Small Letter Es',
    '\u0435': 'Cyrillic Small Letter Ie',
    '\u0456': 'Cyrillic Small Letter Byelorussian-Ukrainian I',
    '\u0458': 'Cyrillic Small Letter Je',
    '\u04CF': 'Cyrillic Small Letter Palochka',
    '\u043E': 'Cyrillic Small Letter O',
    '\u0440': 'Cyrillic Small Letter Er',
    '\u0455': 'Cyrillic Small Letter Dze',
    '\u0445': 'Cyrillic Small Letter Ha',
    '\u0443': 'Cyrillic Small Letter U',
    '\u0501': 'Cyrillic Small Letter Komi De',
    '\u051B': 'Cyrillic Small Letter Qa',
    '\u051D': 'Cyrillic Small Letter We',
    '\u042C': 'Cyrillic Small Letter Soft Sign',
    '\u04D0': 'Cyrillic Small Letter A with Breve',
    '\u04BD': 'Cyrillic Small Letter Abkhasian Che',
    '\u04FB': 'Cyrillic Small Letter Shha with Descender',
    '\u04C3': 'Cyrillic Small Letter Ka with Hook',
    '\u03BF': 'Greek Small Letter Omicron',
    '\u03F1': 'Greek Rho Symbol',
    '\u03C2': 'Greek Small Letter Final Sigma',
    '\u1EA1': 'Latin Small Letter A with Dot Below',
    '\u1E6D': 'Latin Small Letter T with Dot Below',
    '\u1E7F': 'Latin Small Letter V with Dot Below',
    '\u1E93': 'Latin Small Letter Z with Dot Below',
    '\u217E': 'Small Roman Numeral Five Hundred',
    '\u13CF': 'Cherokee Letter Se',
    '\u13C2': 'Cherokee Letter Tli',
    '\u13E6': 'Cherokee Letter Go',
    '\u13B8': 'Cherokee Letter Tlu',
}

def get_banner():
    return f"""{RED}
{RED}88888888888           88  88{END}  88        88  88888888ba   88           
{RED}88                    ""  88{END}  88        88  88      "8b  88           
{RED}88                        88{END}  88        88  88      ,8P  88           
{RED}88aaaaa  8b       d8  88  88{END}  88        88  88aaaaaa8P'  88           
{RED}88\"\"\"\"\"  `8b     d8'  88  88{END}  88        88  88\"\"\"\"88'    88      v4.0     
{RED}88        `8b   d8'   88  88{END}  88        88  88    `8b    88           
{RED}88         `8b,d8'    88  88{END}  Y8a.    .a8P  88     `8b   88           
{RED}88888888888  "8"      88  88{END}   `"Y8888Y"'   88      `8b  88888888  {END}

[ by {RED}Basty-devel - Sebastian Friedrich Nestler + UndeadSec - Alisson Moretto @UndeadSec{END} ]
[ Classroom Edition - IDN Homograph Demonstration ]
"""

def clean_txt(txt):
    for code in (RED, WHITE, GREEN, END, YELLOW, CYAN):
        txt = txt.replace(code, '')
    return txt

def generate_evil_combinations(domain, tld):
    base_domain = domain.split('.')[0]
    replaceable_chars = [c for c in base_domain if c.lower() in EVIL_MAP]
    
    if not replaceable_chars:
        return []
    
    combinations = []
    char_positions = {char: [] for char in set(replaceable_chars)}
    
    # Map character positions
    for idx, char in enumerate(base_domain):
        if char.lower() in EVIL_MAP:
            char_positions[char].append(idx)
    
    # Generate all possible combinations of positions to replace
    all_combinations = []
    for char, positions in char_positions.items():
        char_combs = []
        for r in range(1, len(positions) + 1):
            char_combs.extend(itertools.combinations(positions, r))
        all_combinations.append(char_combs)
    
    # Generate final combinations
    for comb in itertools.product(*all_combinations):
        new_domain = list(base_domain)
        replacements = []
        for positions in comb:
            for pos in positions:
                orig_char = base_domain[pos]
                unicode_char = EVIL_MAP[orig_char.lower()][0]  # Use first variant
                new_domain[pos] = unicode_char
                replacements.append((orig_char, unicode_char, pos))
        evil_domain = ''.join(new_domain) + tld
        combinations.append((evil_domain, replacements))
    
    return combinations

def check_domain_availability(domain):
    try:
        w = whois.whois(domain)
        return w.status is None
    except Exception:
        return True

def check_url_connection(url):
    try:
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path.split('/')[0]
        ip = socket.gethostbyname(host)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)
            s.connect((ip, 80))
        return True
    except Exception:
        return False

class Worker(QThread):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    result = pyqtSignal(str, str)  # text, color
    finished = pyqtSignal()
    
    def __init__(self, domains, options):
        super().__init__()
        self.domains = domains
        self.options = options
        self._is_running = True
        
    def run(self):
        total = len(self.domains)
        for idx, domain in enumerate(self.domains):
            if not self._is_running:
                break
                
            self.status.emit(f"Processing: {domain}")
            self.process_domain(domain, self.options)
            
            # Update progress
            progress = int((idx + 1) / total * 100)
            self.progress.emit(progress)
        
        self.status.emit("Operation completed")
        self.finished.emit()
    
    def stop(self):
        self._is_running = False
        self.status.emit("Operation cancelled")
        
    def process_domain(self, domain, options):
        if '.' not in domain:
            self.result.emit(f"[!] Invalid domain: {domain}", "yellow")
            return
        
        tld = '.' + domain.split('.', 1)[1]
        base_name = domain.split('.')[0]
        
        self.result.emit(f"\n[+] Target Domain: {domain}", "green")
        
        if options['check']:
            try:
                status = "UP" if check_url_connection(domain) else "DOWN"
                color = "green" if status == "UP" else "red"
                self.result.emit(f"[~] Original Connection: {status}", color)
            except Exception as e:
                self.result.emit(f"[!] Connection check failed: {str(e)}", "red")
        
        if options['generate']:
            try:
                combinations = generate_evil_combinations(domain, tld)
            except Exception as e:
                self.result.emit(f"[!] Generation failed: {str(e)}", "red")
                return
            
            if not combinations:
                self.result.emit("[!] No valid character replacements found", "yellow")
                return
            
            self.result.emit(f"[+] Generated {len(combinations)} homograph variants", "green")
            
            for evil_domain, replacements in combinations:
                self.result.emit(f"\n»» Homograph: {evil_domain}", "red")
                
                rep_info = ', '.join(
                    f"{orig}→{uni}(pos:{pos})" 
                    for orig, uni, pos in replacements
                )
                self.result.emit(f"[*] Replacements: {rep_info}", "white")
                
                if options['check']:
                    try:
                        status = "UP" if check_url_connection(evil_domain) else "DOWN"
                        color = "green" if status == "UP" else "red"
                        self.result.emit(f"[~] Connection Test: {status}", color)
                    except Exception as e:
                        self.result.emit(f"[!] Connection test failed: {str(e)}", "red")
                
                if options['availability']:
                    try:
                        available = check_domain_availability(evil_domain)
                        status = "AVAILABLE" if available else "REGISTERED"
                        color = "green" if available else "red"
                        self.result.emit(f"[~] Domain Status: {status}", color)
                    except Exception as e:
                        self.result.emit(f"[!] Availability check failed: {str(e)}", "red")
                
                # Small delay to prevent flooding the UI
                time.sleep(0.1)

class EvilURLGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.worker = None
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle("EvilURL4 Classroom Edition")
        self.setGeometry(100, 100, 900, 700)
        
        # Central widget and layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        # Banner
        banner = QLabel(get_banner())
        banner.setFont(QFont("Courier New", 9))
        banner.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(banner)
        
        # Tabs
        tabs = QTabWidget()
        self.single_tab = QWidget()
        self.batch_tab = QWidget()
        
        # Single domain tab
        single_layout = QVBoxLayout(self.single_tab)
        single_layout.addWidget(QLabel("Domain (e.g., example.com):"))
        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("Enter target domain")
        single_layout.addWidget(self.domain_input)
        
        # Batch processing tab
        batch_layout = QVBoxLayout(self.batch_tab)
        batch_layout.addWidget(QLabel("Input File:"))
        file_layout = QHBoxLayout()
        self.file_input = QLineEdit()
        self.file_input.setPlaceholderText("Select input file")
        browse_btn = QPushButton("Browse")
        browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.file_input)
        file_layout.addWidget(browse_btn)
        batch_layout.addLayout(file_layout)
        
        tabs.addTab(self.single_tab, "Single Domain")
        tabs.addTab(self.batch_tab, "Batch Processing")
        main_layout.addWidget(tabs)
        
        # Options
        options_group = QGroupBox("Options")
        options_layout = QVBoxLayout()
        self.generate_cb = QCheckBox("Generate homograph variants")
        self.generate_cb.setChecked(True)
        self.check_cb = QCheckBox("Check domain connection")
        self.availability_cb = QCheckBox("Check domain availability")
        options_layout.addWidget(self.generate_cb)
        options_layout.addWidget(self.check_cb)
        options_layout.addWidget(self.availability_cb)
        options_group.setLayout(options_layout)
        main_layout.addWidget(options_group)
        
        # Output
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout()
        self.output_text = QTextEdit()
        self.output_text.setReadOnly(True)
        self.output_text.setFont(QFont("Courier New", 10))
        
        # Set dark theme
        palette = QPalette()
        palette.setColor(QPalette.Base, QColor(30, 30, 30))
        palette.setColor(QPalette.Text, QColor(220, 220, 220))
        self.output_text.setPalette(palette)
        
        output_layout.addWidget(self.output_text)
        output_group.setLayout(output_layout)
        main_layout.addWidget(output_group)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        main_layout.addWidget(self.progress_bar)
        
        # Buttons
        btn_layout = QHBoxLayout()
        self.process_btn = QPushButton("Process")
        self.process_btn.clicked.connect(self.start_processing)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self.cancel_processing)
        save_btn = QPushButton("Save Output")
        save_btn.clicked.connect(self.save_output)
        clear_btn = QPushButton("Clear Output")
        clear_btn.clicked.connect(self.clear_output)
        
        btn_layout.addWidget(self.process_btn)
        btn_layout.addWidget(self.cancel_btn)
        btn_layout.addWidget(save_btn)
        btn_layout.addWidget(clear_btn)
        main_layout.addLayout(btn_layout)
        
        # Status bar
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
    def browse_file(self):
        filename, _ = QFileDialog.getOpenFileName(
            self, "Select Input File", "", "Text Files (*.txt);;All Files (*)"
        )
        if filename:
            self.file_input.setText(filename)
    
    def get_options(self):
        return {
            'generate': self.generate_cb.isChecked(),
            'check': self.check_cb.isChecked(),
            'availability': self.availability_cb.isChecked()
        }
    
    def get_domains(self):
        current_tab = self.centralWidget().findChild(QTabWidget).currentIndex()
        if current_tab == 0:  # Single domain
            domain = self.domain_input.text().strip()
            return [domain] if domain else []
        else:  # Batch processing
            filename = self.file_input.text().strip()
            if not filename:
                return []
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    return [line.strip() for line in f if line.strip()]
            except Exception as e:
                self.show_error(f"Error reading file: {str(e)}")
                return []
    
    def start_processing(self):
        domains = self.get_domains()
        if not domains:
            self.show_error("No domains to process!")
            return
        
        options = self.get_options()
        if not any(options.values()):
            self.show_error("Please select at least one option")
            return
        
        # Clear previous output
        self.clear_output()
        self.append_output(get_banner(), "white")
        self.append_output(f"\nProcessing started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", "cyan")
        
        # Setup worker
        self.worker = Worker(domains, options)
        self.worker.result.connect(self.append_output)
        self.worker.status.connect(self.status_bar.showMessage)
        self.worker.progress.connect(self.progress_bar.setValue)
        self.worker.finished.connect(self.on_worker_finished)
        
        # Update UI
        self.progress_bar.setVisible(True)
        self.progress_bar.setRange(0, 100)
        self.process_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        
        # Start worker
        self.worker.start()
    
    def cancel_processing(self):
        if self.worker:
            self.worker.stop()
            self.worker.wait(1000)
            self.on_worker_finished()
            self.append_output("\n[!] Operation cancelled by user", "yellow")
    
    def on_worker_finished(self):
        self.process_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.worker = None
    
    def append_output(self, text, color_name):
        # Map color names to QColor
        color_map = {
            "red": QColor(255, 80, 80),
            "green": QColor(80, 255, 80),
            "yellow": QColor(255, 255, 80),
            "cyan": QColor(80, 255, 255),
            "white": QColor(255, 255, 255)
        }
        
        color = color_map.get(color_name.lower(), QColor(200, 200, 200))
        
        # Create text format
        fmt = QTextCharFormat()
        fmt.setForeground(color)
        
        # Append text
        cursor = self.output_text.textCursor()
        cursor.movePosition(QTextCursor.End)
        cursor.insertText(clean_txt(text) + '\n')
        cursor.select(QTextCursor.LineUnderCursor)
        cursor.mergeCharFormat(fmt)
        
        # Scroll to bottom
        self.output_text.ensureCursorVisible()
    
    def save_output(self):
        content = self.output_text.toPlainText()
        if not content:
            return
            
        filename, _ = QFileDialog.getSaveFileName(
            self, "Save Output", f"evilurl_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            "Text Files (*.txt);;All Files (*)"
        )
        if filename:
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(content)
                self.status_bar.showMessage(f"Output saved to {filename}", 5000)
            except Exception as e:
                self.show_error(f"Error saving file: {str(e)}")
    
    def clear_output(self):
        self.output_text.clear()
    
    def show_error(self, message):
        QMessageBox.critical(self, "Error", message)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Modern style
    
    # Set dark theme
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor(53, 53, 53))
    palette.setColor(QPalette.WindowText, Qt.white)
    palette.setColor(QPalette.Base, QColor(25, 25, 25))
    palette.setColor(QPalette.AlternateBase, QColor(53, 53, 53))
    palette.setColor(QPalette.ToolTipBase, Qt.white)
    palette.setColor(QPalette.ToolTipText, Qt.white)
    palette.setColor(QPalette.Text, Qt.white)
    palette.setColor(QPalette.Button, QColor(53, 53, 53))
    palette.setColor(QPalette.ButtonText, Qt.white)
    palette.setColor(QPalette.BrightText, Qt.red)
    palette.setColor(QPalette.Highlight, QColor(142, 45, 197).lighter())
    palette.setColor(QPalette.HighlightedText, Qt.black)
    app.setPalette(palette)
    
    window = EvilURLGUI()
    window.show()
    sys.exit(app.exec_())