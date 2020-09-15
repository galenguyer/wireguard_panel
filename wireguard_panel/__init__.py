""" A small flask Hello World """

import os
import subprocess
import wg_conf
from base64 import b64encode, b64decode
from flask import Flask, render_template, send_from_directory, request, redirect, url_for
from nacl.public import PrivateKey
from pathlib import Path

APP = Flask(__name__)

# Load file based configuration overrides if present
if os.path.exists(os.path.join(os.getcwd(), 'config.py')):
    APP.config.from_pyfile(os.path.join(os.getcwd(), 'config.py'))
else:
    APP.config.from_pyfile(os.path.join(os.getcwd(), 'config.env.py'))

APP.secret_key = APP.config['SECRET_KEY']

WC_EDITED=False
wc = wg_conf.WireguardConfig(APP.config['WG_CONFIG_PATH'])

@APP.route('/static/<path:path>', methods=['GET'])
def _send_static(path):
    return send_from_directory('static', path)

@APP.route('/')
def _index():
    wc.interface['PublicKey'] = b64encode(bytes(PrivateKey(b64decode(wc.interface['PrivateKey'].encode('ascii'))).public_key)).decode('ascii')
    if_name = Path(APP.config['WG_CONFIG_PATH']).stem
    commit_hash = None
    try:
        commit_hash = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD']) \
                                .strip() \
                                .decode('utf-8')
    # pylint: disable=bare-except
    except:
        commit_hash = None
    return render_template('home.html', commit_hash=commit_hash, if_name=if_name, interface=wc.interface, peers=wc.peers.values(), edited=WC_EDITED)

@APP.route('/newpeer', methods=['GET', 'POST'])
def _newpeer():
    if request.method == 'GET':
        commit_hash = None
        try:
            commit_hash = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD']) \
                                    .strip() \
                                    .decode('utf-8')
        # pylint: disable=bare-except
        except:
            commit_hash = None
        return render_template('newpeer.html', commit_hash=commit_hash)
    elif request.method == 'POST':
        if request.form.get('privkey').strip() != '':
            privkey = request.form.get('privkey')
            pubkey = b64encode(bytes(PrivateKey(b64decode(privkey.encode('ascii'))).public_key)).decode('ascii')
        elif request.form.get('pubkey').strip() != '':
            privkey = None
            pubkey = request.form.get('pubkey')
        else:
            tmpkey = PrivateKey.generate()
            privkey = b64encode(bytes(tmpkey)).decode("ascii")
            pubkey = b64encode(bytes(tmpkey.public_key)).decode("ascii")
        wc.create_peer(pubkey)
        wc.add_peer_attr(pubkey, 'AllowedIps', request.form.get('ips'))
        if request.form.get('psk').strip() != '':
            wc.add_peer_attr(pubkey, 'PresharedKey', request.form.get('psk'))
        global WC_EDITED
        WC_EDITED = True
        return redirect('/')

@APP.route('/save', methods=['POST'])
def _save():
    global WC_EDITED
    wc.write_file()
    WC_EDITED = False
    return redirect('/')

@APP.route('/discard', methods=['POST'])
def _discard():
    global WC_EDITED
    global wc
    wc = wg_conf.WireguardConfig(APP.config['WG_CONFIG_PATH'])
    WC_EDITED = False
    return redirect('/')