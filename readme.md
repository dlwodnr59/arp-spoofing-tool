ARP 스푸핑 프로그램
이 프로그램은 ARP 스푸핑을 이용하여 네트워크 내에 있는 기기들의 정보를 탐지하고 스푸핑하는 기능을 제공합니다.

필요한 라이브러리
PyQt5, 
netifaces, 
scapy, 
psutil



기능
스캔 버튼: 네트워크 내에 있는 모든 기기의 호스트 이름, IP 주소, MAC 주소를 스캔합니다.

Gateway 버튼: 선택한 기기가 Gateway일 경우 IP 주소와 MAC 주소를 출력합니다.

Target 버튼: 선택한 기기가 Target일 경우 IP 주소와 MAC 주소를 출력합니다.

Start Spoofing 버튼: Gateway와 Target의 IP와 MAC 주소를 이용하여 ARP 스푸핑을 시작합니다.

Stop Spoofing 버튼: ARP 스푸핑을 중지합니다.



실행 방법
터미널에서 python3 main.py 명령을 입력하여 실행합니다.



주의사항
이 프로그램은 권한을 필요로 합니다. 루트 권한 또는 관리자 권한으로 실행하세요.
프로그램 사용으로 일어난 일은 저에게 책임이 없습니다.
