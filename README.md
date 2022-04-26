# born2beroot
Project in 42seoul 4th


## subject translation
- Virtual Box를 사용한다
- signature.txt파일만 제출하면 된다. (가상 컴퓨터 가상디스크 서명을 붙여 넣으면된다.)
- 그래픽 인터페이스는 사용되지 않는다.
- 데비안 쓰는것을 추천한다.
- LVM을 사용하여 암호화된 파티션을 2개 이상 생성해야 한다.
- ssh 포트는 4242에서만 실행해야한다.
- 보안상의 이유로 root로 불가능하게 한다.
- 디펜스중에 ssh는 새 계정으로 테스트 해야한다.
- UFW 방화벽으로 운영 체제를 구성해야 하므로 4242포트만 열어둔다.
- 가상머신 시작 시 방화벽이 활성화되어 있어야 한다.
- 가상 머신의 hostname은 자기이름42 이어야한다.
- 평가동안 hostname을 수정해야 한다
- 디펜스중에 새 사용자를 만들고 그룹에 할당해야한다.
- 비밀번호는 30일마다 만료되어야 한다.
- 비밀번호 수정을 허용하는 최소 일수는 2로 설정한다.
- 사용자는 암호가 만료되기 7일전에 경고 메세지를 받는다.
- 비밀번호 10자 이상, 대문자포함, 문자와 숫자 또는 내용이 연속 3개 이상 포함되면 안된다.
- 암호에는 사용자 이름이 포함되면 안된다.
- root의 암호도 규칙을 지켜야한다.
- 이전 암호의 일부가 아닌 7자 이상이어야 한다는 규칙은 root제외 나머지계정 암호규칙이다.
- After setting up your configuration files, you will have to change all the passwords of the accounts present on the virtual machine, including the root account. (해석 잘모르겠음)
- sudo 인증 비밀번호 시도는 3번으로 제한된다.
- sudo 오류 발생시 지정 메시지가 표시되어야 한다.
- sudo 입출력 로그는 /var/log/sudo/ 폴더에 저장해야 한다.
- tty모드를 활성화 해야한다.
- sudo 사용 경로를 /usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin 로 지정한다.
- monitoring.sh 스크립트를 bash에서 구현한다.
- 서버 시작시 monitoring.sh 스크립트는 10분마다 아래 내용을 표시해야 한다. 오류는 없어야 한다.
- **스크립트 내용**
```
- 디펜스 동안 스크립트가 어떻게 작동하는지 설명해야 한다. 수정하지 않고 중단해야 한다.
운영 체제의 아키텍처 및 커널 버전.
물리 프로세서의 수.
가상 프로세서의 수.
서버에서 현재 사용 가능한 RAM 및 사용률(백분율).
서버의 현재 사용 가능한 메모리 및 사용률(백분율).
프로세서의 현재 사용률을 백분율로 표시합니다.
마지막 재부팅 날짜 및 시간.
LVM이 활성 상태인지 여부.
활성 연결 수.
서버를 사용하는 사용자 수.
서버의 IPv4 주소 및 해당 MAC(Media Access Control) 주소.
sudo 프로그램으로 실행된 명령 수.
```

---

### lsblk 명령어
- 부트로더를 sda1에 설치한 것을 확인할 수있다. (subject)

### sudo 설치
-get update (패키지 목록을 업데이트한다.)
- apt-get install sudo (sudo를 설치한다.)
- apt : 패키지를 관리하는 도구

### sudoers
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

### iolog_dir
- 지정한 /var/log/sudo 경로가 없으면 추가한다.
- mkdir /var/log/sudo 명령

### usermod
- info : usermod -aG "그룹" "계정" > 계정의 소속 그룹을 추가한다. (https://dololak.tistory.com/270)
- usermod -aG sudo jaewoo 입력
- login jaewoo 입력
- sudo명령어 아무거나 실행
- su - 입력 (root login)
- cat /var/log/sudo/00/00/01/log 입력 > 다른사용자들의 sudo명령을 확인할 수 있다.

### ufw 설치
- info : 방화벽
- apt-get install ufw -y > 설치
- ufw status verbose > 상태 자세히 
- ufw enable > ufw가능하게 설정 (ufw disable > 불가능)
- ufw default deny > 기본 정책 거부
- ufw allow 4242 > ssh 4242포트 허용, (ufw deny 4242 > 거부)
- ufw status verbose
- (https://webdir.tistory.com/206)

debian vi command : (https://harryp.tistory.com/10)

### ssh 환경설정
- info : (Secure Shell) 원격 호스트에 접속하기 위해 사용되는 프로토콜
- apt install openssh-server > 설치
- vi /etc/ssh/sshd_confing
- #Port 22  > Port 4242 변경
- #PermitRootLogin prohibit-password > PermitRootLogin no 변경 (no일 경우 root로 ssh 로그인 불가) 
  (prohibit-password일 경우 비밀번호를 사용한 ssh로그인 막고 Key파일을 사용해서 ssh로그인 가능)
- systemctl restart ssh > ssh 재실행
- systemctl status ssh > ssh 상태

hostname -I : 가상머신의 ip

### virtualBox 설정
- Tool 옆 Network 클릭
- create 클릭
- born2beroot의 setting 클릭
- Network의 Advanced, Port Fowarding 클릭
- +눌러서 Host IP : vboxnet0의 IP, Host Port : 4242, Guest IP : 가상머신 IP, Guest Port : 4242 설정 후 OK
- Adapter 2 클릭 후 새로만들고 Attached to: Host-only Adapter, Name : vboxnet0 설정후 OK
- 가상머신 실행 후 Mac의 터미널에서 ifconfig 입력시 vboxnet0, IP 확인 가능
- Mac 터미널에서 ssh id@192.168.56.1 -p 4242 > ssh 접근 (ssh key값도 넣어준다)
- 설정에서 막아놓아서 root로 로그인은 불가능

### 패스워드 정책 설정
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

### monitoring.sh 설정
- apt-get -y install sysstat > '리눅스 성능 측정 도구 패키지' 설치
- vi /root/monitoring.sh
- 아래 내용 입력( > 이후는 주석)

```
printf "#Architecture : "
uname -a  > 시스템 정보 전체 출력 (-i, -p옵션 제외)

printf "#CPU physical : "
nproc --all > 시스템에 설치된 총 처리장치 수 출력

printf "#vCPU : "
cat /proc/cpuinfo | grep processor | wc -l  > 전체 코어 수? 출력

printf "#Memory Usage : "
free -m | grep Mem | awk '{printf"%d/%dMB (%.2f%%)\n", $3, $2, $3/$2 * 100}'  > free -m : 메가바이트 단위 옵션의 메모리 출력

printf "#Disk Usage : "
df -a -BM | grep /dev/map | awk '{sum+=$3}END{print sum}' | tr -d '\n'  > 디스크용량 정보를 메가바이트 단위로 출력, 계산
printf "/"
df -a -BM | grep /dev/map | awk '{sum+=$4}END{print sum}' | tr -d '\n'
printf "MB ("
df -a -BM | grep /dev/map | awk '{sum1+=$3 ; sum2+=$4 }END{printf "%d", sum1 / sum2 * 100}' | tr -d '\n'
printf "%%)\n"

printf "#CPU load : "
mpstat | grep all | awk '{printf "%.2f%%\n", 100-$13}'

printf "#Last boot : "
who -b | awk '{printf $3" "$4"\n"}' > 시스템 부팅 날짜 출력 ($3 : 날짜, $4 : 시간)

printf "#LVM use : "
if [ "$(lsblk | grep lvm | wc -l)" -gt 0 ] ; then printf "yes\n" ; else printf "no\n" ; fi  > lvm사용시 yes출력, 아니면 no출력

printf "#Connections TCP : "
ss | grep -i tcp | wc -l | tr -d '\n'  > tcp에 연결 수 출력
printf " ESTABLISHED\n" 

printf "#User log : "
who | wc -l > 현 시스템에 로그인되어있는 사용자 수 출력

printf "#Network : IP "
hostname -I | tr -d '\n'  > 호스트의 ip출력 (즉 가상머신의 ip)
printf "("
ip link show | awk '$1 == "link/ether" {print $2}' | sed '2, $d' | tr -d '\n'
printf ")\n"

printf "#Sudo : "
journalctl _COMM=sudo | wc -l | tr -d '\n'  > sudo의 로그 조회 수 출력
printf " cmd\n"
```

- sysstat : 리눅스 성능 측정 도구 패키지
- /proc/cpuinfo : cpu 코어 개별적인 세부사항 정보들이 담겨있는 파일
- free -m : 메가바이트 단위 옵션의 메모리 출력
- df 명령어 : 리눅스 시스템 전체의 (마운트 된) 디스크 사용량을 확인하는 명령어
- mpstat : cpu 지표 측정
- 쉘 스크립트 if문 : (https://jink1982.tistory.com/48)
- lsblk 명령어 : 리눅스 디바이스 정보를 출력하는 명령어
- lvm : (logical Volumn Manager) 리눅스의 저장 공간을 효율적이고 유연하게 관리하기 위한 커널의 한 부분 > lvm 정보 : (https://greencloud33.tistory.com/41)
- sed '2, $d' : 2번째 행부터 마지막 행까지 삭제
- journalctl : systemd의 로그를 journal로 관리한다. journal을 관리, 조회하는 소프트웨어
- systemd : init 데몬, 요즘 init대신 systemd로 대체하게 된다.

### cron
- chmod +x monitoring.sh  > 실행하능하게 설정
- crontab -e > crontab 수정
``` */10 * * * * /root/monitoring.sh | wall```  > 입력 (wall : 모든 사용자에게 메세지 기록)
```
service crond start   // crontab 시작
service crond stop    // crontab 중지
service crond restart    // crontab 재시작
```

### group
- 그룹 확인 : cat /etc/group
- groupadd user42 > 그룹 추가
- usermod -aG sudo,user42 jaewoo(사용자이름) > 계정의 소속 그룹을 추가 한다.
- usermod -g user42 jaewoo > 계정의 기본 소속 그룹을 변경한다.

### apt & aptitude
#### apt : 소프트웨어의 설치와 제거 처리해주는 패키지 관리 툴

#### aptitude : 사용자 인터페이스를 추가해 사용자와 대화형으로 패키지를 검색해 설치, 제거 가능한 high-level 패키지 관리도구이다.
- apt 보다 방대하다.
- apt-get, get-cache의 기능들을 가지고있다.
- (https://velog.io/@joonpark/aptitude-vs-apt)

### hostname 변경
- hostname 이름 > 재 시작시 다시 돌아옴
- hostnamectl set-hostname 이름 > 영구 변경

### user 전체 보기
- grep /bin/bash /etc/passwd | cut -f1 -d:

### user 추가
- adduser 이름
