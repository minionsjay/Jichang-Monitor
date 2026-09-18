import frida, time, json, threading, http.client
session = frida.attach(1650304)
script = session.create_script(open(r'E:\Hermes-Agent\Jichang-Monitor\hook_hmac_realtime.js', encoding='utf-8').read())
events = []
def on_msg(m, d):
    if m['type'] == 'send':
        print(json.dumps(m['payload'])[:300], flush=True)
        events.append(m['payload'])
script.on('message', on_msg)
script.load()
def trigger():
    time.sleep(3)
    for _ in range(5):
        try:
            c = http.client.HTTPConnection('127.0.0.1', 21081, timeout=5)
            c.request('GET', 'http://example.com/')
            c.getresponse().read(); c.close()
        except: pass
        time.sleep(4)
threading.Thread(target=trigger, daemon=True).start()
time.sleep(45)
print(f'\n共{len(events)}事件')
json.dump(events, open(r'E:\Hermes-Agent\Jichang-Monitor\hmac_realtime.json', 'w'), indent=1)
