""" A small flask Hello World """

import os
import subprocess
import wg_conf
from base64 import b64encode, b64decode
from flask import Flask, render_template, send_from_directory
from nacl.public import PrivateKey

APP = Flask(__name__)

# Load file based configuration overrides if present
if os.path.exists(os.path.join(os.getcwd(), 'config.py')):
    APP.config.from_pyfile(os.path.join(os.getcwd(), 'config.py'))
else:
    APP.config.from_pyfile(os.path.join(os.getcwd(), 'config.env.py'))

APP.secret_key = APP.config['SECRET_KEY']

@APP.route('/static/<path:path>', methods=['GET'])
def _send_static(path):
    return send_from_directory('static', path)

@APP.route('/')
def _index():
    wc = wg_conf.WireguardConfig(APP.config['WG_CONFIG_PATH'])
    wc.interface['PublicKey'] = b64encode(bytes(PrivateKey(b64decode(wc.interface['PrivateKey'].encode('ascii'))).public_key)).decode('ascii')
    commit_hash = None
    try:
        commit_hash = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD']) \
                                .strip() \
                                .decode('utf-8')
    # pylint: disable=bare-except
    except:
        commit_hash = None
    return render_template('home.html', commit_hash=commit_hash, interface=wc.interface)
