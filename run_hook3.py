import frida, time, json, threading, http.client

PID = 1650304
session = frida.attach(PID)
script_src = open(r'E:\Hermes-Agent\Jichang-Monitor\hook_sha256.js', encoding='utf-8').read()
script = session.create_script(script_src)
events = []

def on_message(msg, data):
    if msg['type'] == 'send':
        p = msg['payload']
        events.append(p)
        print(json.dumps(p, ensure_ascii=False)[:300], flush=True)

script.on('message', on_message)
script.load()

def trigger():
    time.sleep(3)
    for _ in range(3):
        try:
            c = http.client.HTTPConnection('127.0.0.1', 21081, timeout=5)
            c.request('GET', 'http://example.com/')
            c.getresponse().read(); c.close()
        except: pass
        time.sleep(3)

threading.Thread(target=trigger, daemon=True).start()
time.sleep(30)
print(f'\n共{len(events)}事件')
json.dump(events, open(r'E:\Hermes-Agent\Jichang-Monitor\sha256_hook_events.json', 'w'), indent=1)
