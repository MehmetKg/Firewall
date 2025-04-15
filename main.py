from PyQt5.QtWidgets import (
    QMainWindow, QApplication, QVBoxLayout, QWidget, QPushButton, QLabel,
    QLineEdit, QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView,
    QListWidget, QTextEdit
)
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtGui import QIcon
from collections import defaultdict
import time
import sys
import socket
import pydivert
import logging

# Loglama
logging.basicConfig(
    filename="Firewall_logs.txt",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def log_to_file(message, level="info"):
    if level == "info":
        logging.info(message)
    elif level == "warning":
        logging.warning(message)
    elif level == "error":
        logging.error(message)


class FirewallWorker(QThread):
    log_signal = pyqtSignal(str, str, str)
    rules_signal = pyqtSignal(str)

    Protocal_map = {
        1: "ICMP", 2: "IGMP", 6: "TCP", 8: "EGP", 9: "IGP", 17: "UDP",
        41: "IPv6", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF",
        132: "SCTP", 112: "VRRP", 137: "IPIP", 143: "PIM", 253: "VISA",
        254: "IPIP", 255: "Reserved",
    }

    def __init__(self, rules, website_filter):
        super().__init__()
        self.rules = rules
        self.website_filter = website_filter
        self.running = True
        self.traffic_tracker = defaultdict(list)
        self.blacklist = set()
        self.whitelist = ["127.0.0.1", "::1"]

    def resolve_url_to_ip(self, url):
        try:
            return socket.gethostbyname(url)
        except socket.gaierror:
            return None

    def get_protocol_name(self, protocol):
        if isinstance(protocol, tuple):
            protocol = protocol[0]
        return self.Protocal_map.get(protocol, f"Bilinmiyor ({protocol})")

    def run(self):
        try:
            with pydivert.WinDivert("tcp or udp") as w:
                for packet in w:
                    if not self.running:
                        break

                    src_ip = packet.src_addr
                    dst_ip = packet.dst_addr
                    protocol = self.get_protocol_name(packet.protocol)
                    current_time = time.time()

                    if src_ip in self.whitelist:
                        w.send(packet)
                        continue
                    if src_ip in self.blacklist:
                        self.rules_signal.emit(f"IP kara listede : {src_ip}")
                        continue
                    if dst_ip in self.website_filter:
                        self.rules_signal.emit(f"Engellendi: {dst_ip} (Web Sitesi)")
                        continue

                    self.traffic_tracker[src_ip].append(current_time)
                    short_window = [ts for ts in self.traffic_tracker[src_ip] if current_time - ts <= 1]
                    long_window = [ts for ts in self.traffic_tracker[src_ip] if current_time - ts <= 10]

                    if len(short_window) > 1000 or len(long_window) > 50000:
                        self.rules_signal.emit(f"DDoS tespit edildi: {src_ip}")
                        self.blacklist.add(src_ip)
                        log_to_file(f"DDoS tespit edildi ve engellendi: {src_ip}", level="warning")
                        continue

                    self.log_signal.emit(src_ip, dst_ip, protocol)
                    log_to_file(f"Paket: {src_ip}:{packet.src_port} -> {dst_ip}:{packet.dst_port}")

                    blocked = False
                    for rule in self.rules:
                        if "tcp" in rule.lower() and protocol.lower() == "tcp":
                            self.rules_signal.emit("TCP engellendi.")
                            blocked = True
                            break
                        elif "udp" in rule.lower() and protocol.lower() == "udp":
                            self.rules_signal.emit("UDP paketi engellendi.")
                            blocked = True
                            break
                        elif rule in f"{packet.src_addr}:{packet.src_port}" or rule in f"{packet.dst_addr}:{packet.dst_port}":
                            self.rules_signal.emit(f"Paket Engellendi: {rule}")
                            log_to_file(f"Kural engellendi: {rule}", level="warning")
                            blocked = True
                            break

                    if not blocked:
                        w.send(packet)
        except Exception as e:
            self.rules_signal.emit(f"Hata: {str(e)}")

    def stop(self):
        self.running = False


class FirewallGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Firewall")
        self.setWindowIcon(QIcon("Icon.ico"))
        self.resize(1000, 700)

        self.rules = []
        self.website_filter = set()
        self.firewall_worker = None

        self.main_widget = QWidget()
        self.setCentralWidget(self.main_widget)
        layout = QVBoxLayout()

        self.start_button = QPushButton("Firewall'u Başlat")
        self.start_button.clicked.connect(self.start_firewall)

        self.stop_button = QPushButton("Firewall'u Durdur")
        self.stop_button.setEnabled(False)
        self.stop_button.clicked.connect(self.stop_firewall)

        self.rule_label = QLabel("Kurallar")
        self.rule_list = QListWidget()
        self.rule_input = QLineEdit()
        self.rule_input.setPlaceholderText("Port veya IP kuralı girin")

        self.add_rule_button = QPushButton("Kural Ekle")
        self.add_rule_button.clicked.connect(self.add_rule)

        self.delete_rule_button = QPushButton("Seçili Kuralı Sil")
        self.delete_rule_button.clicked.connect(self.delete_rule)

        self.network_label = QLabel("Ağ Trafiği")
        self.log_area = QTableWidget()
        self.log_area.setColumnCount(3)
        self.log_area.setHorizontalHeaderLabels(["Kaynak", "Hedef", "Protokol"])
        self.log_area.setEditTriggers(QTableWidget.NoEditTriggers)
        self.log_area.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)

        self.rules_log_label = QLabel("Uygulanan Kurallar")
        self.rules_area = QTextEdit()
        self.rules_area.setReadOnly(True)

        self.website_label = QLabel("Engellenen Web Siteleri")
        self.website_input = QLineEdit()
        self.website_input.setPlaceholderText("Engellenecek siteyi girin")
        self.add_website_button = QPushButton("Web Sitesi Ekle")
        self.add_website_button.clicked.connect(self.add_website)
        self.website_list = QListWidget()

        # Arayüzü birleştir
        layout.addWidget(self.start_button)
        layout.addWidget(self.stop_button)
        layout.addWidget(self.rule_label)
        layout.addWidget(self.rule_list)
        layout.addWidget(self.rule_input)
        layout.addWidget(self.add_rule_button)
        layout.addWidget(self.delete_rule_button)
        layout.addWidget(self.network_label)
        layout.addWidget(self.log_area)
        layout.addWidget(self.rules_log_label)
        layout.addWidget(self.rules_area)
        layout.addWidget(self.website_label)
        layout.addWidget(self.website_input)
        layout.addWidget(self.add_website_button)
        layout.addWidget(self.website_list)

        self.main_widget.setLayout(layout)

    def add_to_traffic_table(self, src, dst, protocol):
        row = self.log_area.rowCount()
        self.log_area.insertRow(row)
        self.log_area.setItem(row, 0, QTableWidgetItem(src))
        self.log_area.setItem(row, 1, QTableWidgetItem(dst))
        self.log_area.setItem(row, 2, QTableWidgetItem(protocol))

    def add_rule(self):
        rule = self.rule_input.text()
        if rule:
            self.rules.append(rule)
            self.rule_list.addItem(rule)
            self.rule_input.clear()
            self.rules_area.append(f"Kural Eklendi: {rule}")
        else:
            QMessageBox.warning(self, "Uyarı", "Geçerli bir kural girin!")

    def delete_rule(self):
        item = self.rule_list.currentItem()
        if item:
            rule = item.text()
            self.rules.remove(rule)
            self.rule_list.takeItem(self.rule_list.row(item))
            self.rules_area.append(f"Kural Silindi: {rule}")
        else:
            QMessageBox.warning(self, "Uyarı", "Silmek için bir kural seçin!")

    def add_website(self):
        url = self.website_input.text()
        if url:
            ip = socket.gethostbyname(url)
            if ip:
                self.website_filter.add(ip)
                self.website_list.addItem(f"{url} ({ip})")
                self.rules_area.append(f"Web sitesi filtresine eklendi: {url} ({ip})")
                self.website_input.clear()
            else:
                QMessageBox.warning(self, "Uyarı", "Geçerli bir site girin!")
        else:
            QMessageBox.warning(self, "Uyarı", "Bir URL girin!")

    def start_firewall(self):
        if not self.firewall_worker:
            self.firewall_worker = FirewallWorker(self.rules, self.website_filter)
            self.firewall_worker.log_signal.connect(self.add_to_traffic_table)
            self.firewall_worker.rules_signal.connect(self.rules_area.append)
            self.firewall_worker.start()
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.rules_area.append("Firewall başlatıldı.")

    def stop_firewall(self):
        if self.firewall_worker:
            self.firewall_worker.stop()
            self.firewall_worker.quit()
            self.firewall_worker.wait()
            self.firewall_worker = None
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.rules_area.append("Firewall durduruldu.")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    gui = FirewallGUI()
    gui.show()
    sys.exit(app.exec_())


