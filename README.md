# Net Filter 1 Million
- dest port가 80번인 http request 패킷의 host를 검사하고, BlackList에 존재하는 URL이면 패킷을 DROP하는 프로그램
- 100만개의 URL 목록을 이용하여 지정된 사이트 접속을 차단하는 프로그램
- 각 URL의 첫글자를 이용하여 인덱스 배열을 생성하고, 해당 첫 글자 범위 내애서 문자열 일치 검사 수행

## Usage
- syntax : netfilter-test [blacklist file]
- sample : netfilter-test sample.txt

## Prepare
- 패킷들이 Netfilter를 거치도록 iptable 설정
```
sudo iptables -A INPUT -j NFQUEUE --queue-num 0
sudo iptables -A OUTPUT -j NFQUEUE --queue-num 0
```

## test set
- mi.com
- test.gilgil.net
- nike.com

## Test method
- ``` $wget facebook.com --no-hsts```
- --no-hsts 옵션을 이용해서 80번 포트로 요청을 보내게 합니다.
- 위 옵션을 사용하지 않으면 https 패킷(443 포트)으로 전송되어 필터링이 안됨

## 실행 화면
- <img src="https://github.com/ehn1225/Netfilter_1M/assets/5174517/7fe93105-13c2-4e1c-a50a-8cd4b2d89356"  width="700"/>
- 프로그램 실행 전(첫번째 명령)에는 ```wget```으로 정상적인 웹페이지 접속이 가능함
- 프로그램 실행 후(두번째 명령)에는 웹페이지 접속이 안되는 것을 확인할 수 있음
- 분할된 터미널 아래 부분을 보면, 프로그램에 의해 test.gilgil.net 패킷이 드랍된 것을 확인할 수 있음

## Reference
[Alexa Top 1 Million](https://github.com/mozilla/cipherscan/tree/master/top1m)
