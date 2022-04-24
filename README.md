# born2beroot
Project in 42seoul 4th


## description

#### lsblk
- 부트로더를 sda1에 설치 (subject)

#### sudo 설치
- apt-get update (패키지 목록을 업데이트한다.)
- apt-get install sudo (sudo를 설치한다.)
- apt : 패키지를 관리하는 도구

#### sudoers
- info : sudo명령어를 사용할 수 있는 계정을 관리하는 설정파일이다.
- etc/sudoers 에 접근한다.
- 파일을 읽어보면 sudoers파일은 visudo로만 수정되어야 하고 root명령으로만 해야한다고 적혀있다.
- secure_path에 ":/snap/bin" 추가하여 경로 설정한다. (subject)
- Defaults  authfail_message="권한 부여 실패 메세지" 추가 > 권한실패시 나오는 메세지를 지정한다.
- Defaults  badpass_message="비번 틀릴때 메세지" 추가 > 비밀번호 틀릴 때 나오는 메세지를 지정한다.
- Defaults  iolog_dir="/var/log/sudo/" 추가 > sudo명령어 입출력 기록 경로를 지정한다.
- Defaults log_input 추가 > input, output 매개변수 사용하면 sudo가 tty에서 명령을 실행하고 모든 사용자의 입출력을
- Defaults log_output 추가 > 화면에 수신 가능하게 기록한다.
- Defaults requiretty 추가 > tty를 할당 받지 않은 shell에서는 sudo를 사용하지 못하게 하는 옵션이다. (https://kldp.org/node/155210)
- Defaults passwd_tries=3 추가 > 비밀번호 시도할 수 있는 횟수를 3으로 지정한다.

#### iolog_dir
- 지정한 /var/log/sudo 경로가 없으면 추가한다.
- mkdir /var/log/sudo 명령

#### usermod
- infor : usermod -aG "그룹" "계정" > 계정의 소속 그룹을 추가한다. (https://dololak.tistory.com/270)
- usermod -aG sudo jaewoo 입력
- login jaewoo 입력
- sudo명령어 아무거나 실행
- su - 입력 (root login)
- cat /var/log/sudo/00/00/01/log 입력 > 다른사용자들의 sudo명령을 확인할 수 있다.

#### ufw 설치
- apt-get install ufw -y > 설치
- ufw status verbose > 상태 자세히 
- ufw enable > ufw가능하게 설정 (ufw disable > 불가능)
- ufw default deny > 기본 정책 거부
- ufw allow 4242 > ssh 4242포트 허용, (ufw deny 4242 > 거부)
- ufw status verbose
- (https://webdir.tistory.com/206)

debian vi command : (https://harryp.tistory.com/10)

#### ssh 환경설정
- apt install openssh-server > 설치
- vi /etc/ssh/sshd_confing
- #Port 22  > Port 4242 변경
- #PermitRootLogin prohibit-password > PermitRootLogin no 변경 (no일 경우 root로 ssh 로그인 불가) 
  (prohibit-password일 경우 비밀번호를 사용한 ssh로그인 막고 Key파일을 사용해서 ssh로그인 가능)
- systemctl restart ssh > ssh 재실행
- systemctl status ssh > ssh 상태

hostname -I : 가상머신의 ip

#### virtualBox 설정
- Tool 옆 Network 클릭
- create 클릭
- born2beroot의 setting 클릭
- Network의 Advanced, Port Fowarding 클릭
- +눌러서 Host IP : vboxnet0의 IP, Host Port : 4242, Guest IP : 가상머신 IP, Guest Port : 4242 설정 후 OK
- Adapter 2 클릭 후 새로만들고 Attached to: Host-only Adapter, Name : vboxnet0 설정후 OK
- 가상머신 실행 후 Mac의 터미널에서 ifconfig 입력시 vboxnet0, IP 확인 가능
- Mac 터미널에서 ssh id@192.168.56.1 -p 4242 > ssh 접근 (ssh key값도 넣어준다)
- 설정에서 막아놓아서 root로 로그인은 불가능

#### 패스워드 정책 설정
- vi /etc/login.defs 에서 관리한다.
- PASS_MAX_DAYS 30 변경 > 비밀번호를 최대로 사용가능한 일 수
- PASS_MIN_DAYS 2 변경 > 비밀번호를 최소 사용가능한 일 수
- PASS_WARN_AGE 7 변경 > 비밀번호 만료 7일전 경고해준다.
- 저장 후 나가기
- apt-get -y install libpam-pwquality > 설치
- vi /etc/pam.d/common-password
- retry=3 뒤에 띄어쓰기 구분으로 추가하기 > minlen=10 ucredit=-1 lcredit=-1 dcredit=-1 maxrepeat=3 reject_username enforce_for_root difok=7
- 저장 후 나가기

passwd -e jaewoo : jaewoo(사용자)의 비밀번호를 강제로 만료시키기
passwd 명령어 (https://itwiki.kr/w/%EB%A6%AC%EB%88%85%EC%8A%A4_passwd(%EB%AA%85%EB%A0%B9%EC%96%B4))

#### monitoring.sh 설정
- 내일하기.
- 
