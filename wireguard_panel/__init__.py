import os
import subprocess
import urllib.parse
from base64 import b64encode, b64decode
from pathlib import Path

import wg_conf
from flask import Flask, render_template, send_from_directory, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, login_required, current_user
from flask_sqlalchemy import SQLAlchemy
from nacl.public import PrivateKey
from werkzeug.security import generate_password_hash, check_password_hash

APP = Flask(__name__)

# Load file based configuration overrides if present
if os.path.exists(os.path.join(os.getcwd(), 'config.py')):
    APP.config.from_pyfile(os.path.join(os.getcwd(), 'config.py'))
else:
    APP.config.from_pyfile(os.path.join(os.getcwd(), 'config.env.py'))

APP.secret_key = APP.config['SECRET_KEY']
APP.jinja_env.filters['quote'] = lambda u: urllib.parse.quote(u)

db = SQLAlchemy(APP)
APP.logger.info('SQLAlchemy pointed at ' + repr(db.engine.url))
from .models import *
db.create_all()

login_manager = LoginManager()
login_manager.login_view = '/login'
login_manager.init_app(APP)

@login_manager.user_loader
def load_user(user_id):
        # since the user_id is just the primary key of our user table, use it in the query for the user
        return User.query.get(int(user_id))

_admin_user = User.query.filter_by(username='admin').first()
if _admin_user:
    _admin_user.password = generate_password_hash(APP.config['APP_ADMIN_PASSWORD'], method='sha256')
    db.session.commit()
else:
    _admin_user = User(username='admin', password=generate_password_hash(APP.config['APP_ADMIN_PASSWORD'], method='sha256'))
    db.session.add(_admin_user)
    db.session.commit()

commit_hash = None
try:
    commit_hash = subprocess.check_output(['git', 'rev-parse', '--short', 'HEAD']) \
        .strip() \
        .decode('utf-8')
# pylint: disable=bare-except
except:
    pass

WC_EDITED=False
WG_CONF = wg_conf.WireguardConfig(APP.config['WG_CONFIG_PATH'])

@APP.route('/static/<path:path>', methods=['GET'])
def _send_static(path):
    return send_from_directory('static', path)

@APP.route('/')
@login_required
def _index():
    WG_CONF.interface['PublicKey'] = b64encode(bytes(PrivateKey(
        b64decode(WG_CONF.interface['PrivateKey'].encode('ascii'))).public_key)).decode('ascii')
    if_name = Path(APP.config['WG_CONFIG_PATH']).stem
    return render_template('home.html', commit_hash=commit_hash, if_name=if_name,
        interface=WG_CONF.interface, peers=WG_CONF.peers.values(), edited=WC_EDITED, username=current_user.username)

@APP.route('/newpeer', methods=['GET', 'POST'])
@login_required
def _newpeer():
    if request.method == 'GET':
        commit_hash = None
        return render_template('newpeer.html', commit_hash=commit_hash)
    elif request.method == 'POST':
        if request.form.get('privkey').strip() != '':
            privkey = request.form.get('privkey')
            pubkey = b64encode(bytes(
                PrivateKey(b64decode(privkey.encode('ascii'))).public_key)).decode('ascii')
        elif request.form.get('pubkey').strip() != '':
            privkey = None
            pubkey = request.form.get('pubkey')
        else:
            tmpkey = PrivateKey.generate()
            privkey = b64encode(bytes(tmpkey)).decode('ascii')
            pubkey = b64encode(bytes(tmpkey.public_key)).decode('ascii')
        WG_CONF.create_peer(pubkey)
        WG_CONF.add_peer_attr(pubkey, 'AllowedIPs', request.form.get('ips'))
        if request.form.get('psk').strip() != '':
            WG_CONF.add_peer_attr(pubkey, 'PresharedKey', request.form.get('psk'))
        global WC_EDITED
        WC_EDITED = True
        return redirect('/')

@APP.route('/save', methods=['POST'])
@login_required
def _save():
    global WC_EDITED
    WG_CONF.write_file()
    WC_EDITED = False
    return redirect('/')

@APP.route('/discard', methods=['POST'])
@login_required
def _discard():
    global WC_EDITED
    global WG_CONF
    WG_CONF = wg_conf.WireguardConfig(APP.config['WG_CONFIG_PATH'])
    WC_EDITED = False
    return redirect('/')

@APP.route('/editpeer', methods=['GET', 'POST'])
@login_required
def _editpeer():
    pubkey = urllib.parse.unquote(request.args.get('peer'))
    if request.method == 'GET':
        return render_template('editpeer.html', peer=WG_CONF.peers[pubkey])
    elif request.method == 'POST':
        global WC_EDITED
        WG_CONF.set_peer_attr(pubkey, 'AllowedIPs', request.form.get('ips'))
        if request.form.get('psk').strip() != '':
            WG_CONF.set_peer_attr(pubkey, 'PresharedKey', request.form.get('psk'))
        else:
            WG_CONF.del_peer_attr(pubkey, 'PresharedKey')
        WC_EDITED = True
        return redirect('/')


@APP.route('/deletepeer', methods=['POST'])
@login_required
def _deletepeer():
    pubkey = urllib.parse.unquote(request.args.get('peer'))
    global WC_EDITED
    WG_CONF.del_peer(pubkey)
    WC_EDITED = True
    return redirect('/')

@APP.route('/login', methods=['GET'])
def _login_get():
    return render_template('login.html', commit_hash=commit_hash)

@APP.route('/login', methods=['POST'])
def login_post():
    username = request.form.get('username') if request.form.get('username') else 'admin'
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    user = User.query.filter_by(username=username).first()

    # check if the user actually exists
    # take the user-supplied password, hash it, and compare it to the hashed password in the database
    if not user or not check_password_hash(user.password, password):
        flash('Please check your login details and try again.')
        return redirect('/login') # if the user doesn't exist or password is wrong, reload the page

    # if the above check passes, then we know the user has the right credentials
    login_user(user, remember=remember)
    return redirect('/')