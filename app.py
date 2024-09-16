from flask import Flask, render_template, request, flash
from flask import jsonify
import pandas as pd
import time
import json
from datetime import datetime, timedelta
import hashlib
import requests
import threading
from flask import redirect, url_for, Response, stream_with_context
from flask_socketio import SocketIO, emit
from sshtunnel import SSHTunnelForwarder
from pymongo import MongoClient
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user


app = Flask(__name__)
app.secret_key = "your_secret_key"  
socketio = SocketIO(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


loop_active = False
user_path = "user.xlsx"
black_list_path = "black_list.xlsx" 
white_list_path= "white_list.xlsx"

is_login = False

def get_list(file_path):
	df = pd.read_excel(file_path)
	return df
@app.route('/', methods=['GET', 'POST'])
def default():
    return render_template('/sign-in.html')

def convert_df_to_dict(df):
    users = {}
    for _, row in df.iterrows():
        users[row['username']] = {'password': row['password']}
    return users

def get_users():
    df = pd.read_excel(user_path)
    return df
    


@app.route('/virus_check', methods=['GET', 'POST'])
@login_required
def virus_check():
    black_list = get_list(black_list_path)
    white_list = get_list(white_list_path)
    df_normal = pd.DataFrame()
    df_malicious = pd.DataFrame()
    a = df_normal.shape[0]
    b = df_malicious.shape[0]

    return render_template('virus_check.html', black_list_new = black_list.to_string(index=False, header=False),white_list_new = white_list.to_string(index=False, header=False),df_malicious = df_malicious.to_string(index=False, header=False), df_normal = df_normal.to_string(index=False, header=False), a=a, b=b)

@app.route('/tables', methods=['GET', 'POST'])
@login_required
def tables():
    return render_template('tables.html')


@app.route('/ip_upload', methods=['GET', 'POST'])
@login_required
def ip_upload():

    file_name = request.form.get('a')
    df_malicious, df_normal = check(file_name)

    a = df_normal.shape[0]
    b = df_malicious.shape[0]
    
    black_list = get_list(black_list_path)
    white_list = get_list(white_list_path)

    black_list_new = pd.concat([black_list, df_malicious], ignore_index=True)
    white_list_new = pd.concat([white_list, df_normal], ignore_index=True)

    append_data_to_excel(black_list_new, white_list_new)
    #, df_malicious = df_malicious, df_normal = df_normal, black_list_new = black_list_new
    print(df_malicious)
    return render_template('virus_check.html', df_malicious = df_malicious.to_string(index=False, header=False), df_normal = df_normal.to_string(index=False, header=False), black_list_new = black_list_new.to_string(index=False, header=False),white_list_new = white_list_new.to_string(index=False, header=False),a=a, b=b)

@app.route('/ip_upload_2', methods=['GET', 'POST'])
@login_required
def ip_upload_2():
    ip_list_json = request.form.get('ip_list', None)
    ip_list = json.loads(ip_list_json)
    df_ip = pd.DataFrame(ip_list, columns=['ip'])
    df_malicious, df_normal = check_2(df_ip)

    a = df_normal.shape[0]
    b = df_malicious.shape[0]

    black_list = get_list(black_list_path)
    white_list = get_list(white_list_path)

    black_list_new = pd.concat([black_list, df_malicious], ignore_index=True)
    white_list_new = pd.concat([white_list, df_normal], ignore_index=True)

    append_data_to_excel(black_list_new, white_list_new)
    return render_template('virus_check.html', df_malicious = df_malicious.to_string(index=False, header=False), df_normal = df_normal.to_string(index=False, header=False), black_list_new = black_list_new.to_string(index=False, header=False),white_list_new = white_list_new.to_string(index=False, header=False),a=a, b=b)


def get_user(file_path):
	df = pd.read_excel(file_path)
	df.columns = ['user']
	return df   

def check(file_name):
    new_ip_list = get_unique_ip_list(file_name)
    api_key = '991b2155df7d9dc2dad646878f5ba4892163d9ccf6b573c68d5afedbcf8f00be'
    df_to_check = pd.DataFrame(new_ip_list, columns=['ip'])
    df_result = auto_check_virus_total(df_to_check, api_key)
    df_malicious = df_result[df_result['check_result'] != 0]
    df_normal = df_result[df_result['check_result'] == 0]
    return pd.DataFrame(df_malicious['ip']), pd.DataFrame(df_normal['ip'])

def check_2(df):
    new_ip_list = get_unique_ip_list_2(df)
    api_key = '991b2155df7d9dc2dad646878f5ba4892163d9ccf6b573c68d5afedbcf8f00be'
    df_to_check = pd.DataFrame(new_ip_list, columns=['ip'])
    df_result = auto_check_virus_total(df_to_check, api_key)
    df_malicious = df_result[df_result['check_result'] != 0]
    df_normal = df_result[df_result['check_result'] == 0]
    return pd.DataFrame(df_malicious['ip']), pd.DataFrame(df_normal['ip'])

def auto_check_virus_total(df_a, api_key):
    results = []
    for item in df_a['ip'].tolist():
        result = check_virus_total(item, api_key)
        results.append({
            'ip': item,
            'check_result': result
        })
    return pd.DataFrame(results)

def check_virus_total(item, api_key):
    url = f"https://www.virustotal.com/api/v3/{'ip_addresses' if item.count('.') == 3 else 'domains'}/{item}"
    headers = {
        "x-apikey": api_key
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        a = response.json()
        return a['data']['attributes']['last_analysis_stats']['malicious']
    else:
        return None


def get_unique_ip_list(file_name):
    ip_list = get_list(file_name)
    ip_list = ip_list['ip'].tolist()
    black_list = get_list(black_list_path)
    white_list = get_list(white_list_path)
    new_ip_list = [ip for ip in ip_list if ip not in black_list and ip not in white_list]
    return new_ip_list

def get_unique_ip_list_2(ip_list):
    ip_list = ip_list['ip'].tolist()
    black_list = get_list(black_list_path)
    white_list = get_list(white_list_path)
    new_ip_list = [ip for ip in ip_list if ip not in black_list and ip not in white_list]
    return new_ip_list



def append_data_to_excel(black_list, white_list):
    black_list = pd.DataFrame(black_list)
    white_list = pd.DataFrame(white_list)
    black_list.to_excel(black_list_path, index=False)
    white_list.to_excel(white_list_path, index=False)
    return 0






def get_database(file_path):
	df = pd.read_excel(file_path)
	df.columns = ['ip']
	return df

def filtering(df, list):
	df_filtered = pd.DataFrame(columns = df.columns)
	for _,row in df.iterrows():
		a = row
		if any(key in str(a['DESCRIPTION']) for key in list):
			df_filtered = df_filtered._append(a, ignore_index = True)
	return df_filtered

def get_filter(formatted_date_1, formatted_date_2):
	filter = {"time_receive":{"$gte": formatted_date_1,"$lte": formatted_date_2 }}
	name = str(formatted_date_1) + '-' + str(formatted_date_2)
	return filter,name

def raw_to_df(result):
	data = {'MAC': [],'IP': [],'UNIT_NAME': [],'USER_NAME': [],'UNIT_FULL_NAME': [],'ALERT_TYPE': [],'ALERT_LEVEL_ID': [], 'TIME_RECEIVE': [],'DESCRIPTION': []}
	for record in result:
		data['MAC'].append(str(record['mac']))
		data['IP'].append(str(record['ip']))
		data['UNIT_NAME'].append(str(record['unit_full_name']))
		data['USER_NAME'].append(str('Chua dinh danh'))
		data['UNIT_FULL_NAME'].append(str(record['unit_full_name']))
		data['ALERT_TYPE'].append(str(record['alert_type']))
		data['ALERT_LEVEL_ID'].append(str(record['alert_level_id']))
		data['TIME_RECEIVE'].append(str(record['time_receive']))
		data['DESCRIPTION'].append(str(record.get('alert_info', {}).get('description', 'No description available')))
	df = pd.DataFrame(data)
	return df

def get_mongo_data(ssh_host, ssh_port, ssh_user, ssh_password, mongo_host, mongo_port, mongo_db, mongo_collection, filter, sample_size=10):
	print('start 1')
	with SSHTunnelForwarder((ssh_host, ssh_port),
	ssh_username=ssh_user,
	ssh_password=ssh_password,
	
	remote_bind_address=(mongo_host, mongo_port)
	) as tunnel:
		client = MongoClient('127.0.0.1', tunnel.local_bind_port)
		db = client[mongo_db]
		collection = db[mongo_collection]
		result = list(collection.find(filter).limit(100000))	
	print('done 1')
	return result

def core():
    ssh_host = "86.64.60.71"
    ssh_port = 22
    ssh_user = 'root'
    ssh_password = 'P52abc@123456'

    mongo_host = 'localhost.localdomain'
    mongo_port = 27017
    mongo_db = 'fms_v3'
    mongo_collection = 'events'
    database_path = black_list_path
    a = 1
    global loop_active
    while loop_active:
        start_time = datetime.now()		
        before_start = start_time - timedelta(minutes=5)

        filter,name = get_filter(before_start.strftime("%Y-%m-%d %H:%M:%S"), start_time.strftime("%Y-%m-%d %H:%M:%S"))
        #result1 = get_mongo_data(ssh_host, ssh_port, ssh_user, ssh_password, mongo_host, mongo_port, mongo_db, mongo_collection, filter, sample_size=10)
        #df = raw_to_df(result1)
        #df = pd.DataFrame(df)
        df = pd.read_excel(r'2024-08-19-2024-08-20-records.xlsx')
        database = get_database(database_path)
        rule = database['ip'].tolist()
        df_filtered = filtering(df, rule)

        count = len(df_filtered)
        print(f"There are {count} alert!")
        a = a + 1

        end_time = datetime.now()
        elapsed_time = end_time - start_time
        sleep_time =  max(0, (timedelta(seconds=3) - elapsed_time).total_seconds())
        time.sleep(sleep_time)
        data = df_filtered.to_json(orient='records')
        if loop_active:
            socketio.emit('new_data', data)

@app.route('/start', methods=['GET', 'POST'])
@login_required
def start():
    global loop_active
    if not loop_active:
        loop_active = True
        print("start")
        processing_thread = threading.Thread(target=core)
        processing_thread.daemon = True
        processing_thread.start()
        return '1'
    return '0'

def generate_data():
    global loop_active
    print("vào hàm lặp")
    while loop_active:
        print("Lặp")
        time.sleep(2)
        new_data = {
            'Name': ['Row 1'],
            'Status': ['pending']
        }
        df = pd.DataFrame(new_data)
        data = df.to_json(orient='records')
        socketio.emit('new_data', data)
        print(data)


@app.route('/end', methods=['GET', 'POST'])
@login_required
def end():
    print("vào end")
    global loop_active
    loop_active = False 
    return render_template('tables.html')



# đây là cho login
class User(UserMixin):
    def __init__(self, id):
        self.id = id

users = convert_df_to_dict(get_users())

#users = {'a': {'password': 'a'}}
@login_manager.user_loader
def load_user(user_id):
    if user_id in users:
        return User(user_id)
    return None
@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')

    hash_hex = hashlib.sha256(password.encode()).hexdigest()


    if email in users and users[email]['password'] == hash_hex:
        user = User(email)
        login_user(user)
        return jsonify({'status': 'success', 'message': 'Đăng nhập thành công'})
    else:
        return jsonify({'status': 'error', 'message': 'Email hoặc mật khẩu không đúng'}), 401

@app.route('/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'status': 'success', 'message': 'Đăng xuất thành công'})

@app.route('/protected')
@login_required
def protected():
    return f'Logged in as: {current_user.id}'

#if __name__ == '__main__':
#    socketio.run(app, debug=True)
if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=5000, debug=True)
