import frida, sys, time, json, threading
import http.client

PID = 1650304
session = frida.attach(PID)
script_src = open(r'E:\Hermes-Agent\Jichang-Monitor\hook_bcrypt.js', encoding='utf-8').read()
script = session.create_script(script_src)
events = []

def on_message(message, data):
    if message['type'] == 'send':
        events.append(message['payload'])
        p = message['payload']
        if p.get('t') == 'ready':
            print('[hook ready]', flush=True)
        else:
            print(json.dumps(p, ensure_ascii=False)[:300], flush=True)
    else:
        print('[err]', str(message)[:150], flush=True)

script.on('message', on_message)
script.load()

# 触发流量 → 生成带签名的请求
def trigger():
    time.sleep(3)
    for _ in range(4):
        try:
            c = http.client.HTTPConnection('127.0.0.1', 21081, timeout=6)
            c.request('GET', 'http://example.com/')
            c.getresponse().read()
            c.close()
        except Exception:
            pass
        time.sleep(4)

threading.Thread(target=trigger, daemon=True).start()
time.sleep(45)
print(f'\n共捕获 {len(events)} 个事件', flush=True)
json.dump(events, open(r'E:\Hermes-Agent\Jichang-Monitor\bcrypt_events.json', 'w'), indent=1)
