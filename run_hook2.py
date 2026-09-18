import frida, sys, time, json, threading
import http.client
PID = 1650304
session = frida.attach(PID)
script_src = open(r'E:\Hermes-Agent\Jichang-Monitor\hook_nfx.js', encoding='utf-8').read()
script = session.create_script(script_src)
events = []
def on_message(message, data):
    if message['type'] == 'send':
        events.append(message['payload'])
        print(json.dumps(message['payload'], ensure_ascii=False)[:280], flush=True)
    else:
        print('[err]', str(message)[:120], flush=True)
script.on('message', on_message)
script.load()
def trigger():
    time.sleep(4)
    for _ in range(3):
        try:
            c = http.client.HTTPConnection('127.0.0.1', 21081, timeout=6)
            c.request('GET', 'http://example.com/')
            c.getresponse().read(); c.close()
        except Exception: pass
        time.sleep(5)
threading.Thread(target=trigger, daemon=True).start()
time.sleep(40)
print(f'\n共 {len(events)} 事件', flush=True)
json.dump(events, open(r'E:\Hermes-Agent\Jichang-Monitor\nfx_events.json', 'w'), indent=1)
