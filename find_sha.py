import frida, time, json
session = frida.attach(1650304)
script = session.create_script(open(r'E:\Hermes-Agent\Jichang-Monitor\hook_find_sha.js', encoding='utf-8').read())
def on_msg(m, d):
    if m['type'] == 'send':
        print(json.dumps(m['payload'])[:200])
script.on('message', on_msg)
script.load()
time.sleep(10)
