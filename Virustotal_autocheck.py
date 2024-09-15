import pandas as pd
import requests
from tkinter import filedialog
import tkinter as tk
import math
from tkinter import messagebox

excel_path = ''

def get_list(file_path):
	df = pd.read_excel(file_path)
	return df

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
    
def auto_check_virus_total(df_a, api_key):
    results = []
    for item in df_a['ip'].tolist():
        result = check_virus_total(item, api_key)
        results.append({
            'ip': item,
            'check_result': result
        })
    return pd.DataFrame(results)


def select_file(label):
    global excel_path
    excel_path = filedialog.askopenfilename()
    label.config(text=excel_path)
    return excel_path

def check():
    new_ip_list = get_unique_ip_list()
    api_key = '991b2155df7d9dc2dad646878f5ba4892163d9ccf6b573c68d5afedbcf8f00be'
    df_to_check = pd.DataFrame(new_ip_list, columns=['ip'])
    df_result = auto_check_virus_total(df_to_check, api_key)
    df_malicious = df_result[df_result['check_result'] != 0]
    df_normal = df_result[df_result['check_result'] == 0]
    return pd.DataFrame(df_malicious['ip']), pd.DataFrame(df_normal['ip'])


def start_button(entry_white_ip, entry_black_ip):
    if excel_path == '':
        messagebox.showwarning("Thông báo", "Chưa chọn file")
    else: 
        df_malicious, df_normal = check()

        black_list = get_list('C:\\Users\\PC\\Documents\\FMS_logs_collector\\Virustotal_autocheck\\black_list.xlsx')
        white_list = get_list('C:\\Users\\PC\\Documents\\FMS_logs_collector\\Virustotal_autocheck\\black_list.xlsx')

        black_list_new = pd.concat([black_list, df_malicious], ignore_index=True)
        white_list_new = pd.concat([white_list, df_normal], ignore_index=True)

        append_data_to_excel(black_list_new, white_list_new)

        if len(df_normal) != 0:
            for ip in df_normal['ip']:
                entry_white_ip.insert(tk.END, f"{ip}\n")
        if len(df_malicious) != 0:
            for ip in df_malicious['ip']:
                entry_black_ip.insert(tk.END, f"{ip}\n")
        messagebox.showwarning("Thông báo", f"Phát hiện {len(df_malicious)} IOCs độc hại !!!")
    
def append_data_to_excel(black_list, white_list):
    black_list = pd.DataFrame(black_list)
    white_list = pd.DataFrame(white_list)
    black_list.to_excel('C:\\Users\\PC\\Documents\\FMS_logs_collector\\Virustotal_autocheck\\black_list.xlsx', index=False)
    white_list.to_excel('C:\\Users\\PC\\Documents\\FMS_logs_collector\\Virustotal_autocheck\\white_list.xlsx', index=False)
    return 0
    
def get_unique_ip_list():
    ip_list = get_list(excel_path)
    ip_list = ip_list['ip'].tolist()
    black_list = list(get_list('C:\\Users\\PC\\Documents\\FMS_logs_collector\\Virustotal_autocheck\\black_list.xlsx'))
    white_list = list(get_list('C:\\Users\\PC\\Documents\\FMS_logs_collector\\Virustotal_autocheck\\black_list.xlsx'))
    new_ip_list = [ip for ip in ip_list if ip not in black_list and ip not in white_list]
    return new_ip_list

def create_file_selector_window_2():
    root = tk.Tk()
    root.title("Virustotal_checker")
    
    label_file_path = tk.Label(root, text="No file selected")
    label_file_path.grid(column=0, row=0, padx=10, pady=10, columnspan=4, sticky='ew')

    button_select_file = tk.Button(root, text="Select File", command=lambda: select_file(label_file_path))
    button_select_file.grid(column=0, row=1, padx=10, pady=10, columnspan=4, sticky='ew')

    label_black_ip = tk.Label(root, text="MALICIOUS")
    label_black_ip.grid(column=0, row=3, padx=10, pady=10, sticky='e')
    entry_black_ip = tk.Text(root, height=5, width=20)
    entry_black_ip.grid(column=1, row=3, padx=10, pady=10)

    label_white_ip = tk.Label(root, text="NORMAL")
    label_white_ip.grid(column=2, row=3, padx=10, pady=10, sticky='e')
    entry_white_ip = tk.Text(root, height=5, width=20)
    entry_white_ip.grid(column=3, row=3, padx=10, pady=10)
    
    button_start = tk.Button(root, text="Start", command=lambda:start_button(entry_white_ip, entry_black_ip))
    button_start.grid(column=0, row=2, padx=10, pady=10, columnspan=4, sticky='ew')

    root.mainloop()

create_file_selector_window_2()

