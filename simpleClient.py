import socket
import threading
import json
from cryptoUtil import AESUtil, RSAUtil
import os,pathlib
from Crypto.Random import get_random_bytes

class DekuClient():

    def __init__(self,domain="127.0.0.1",port=8000,key="我是传输的密码啦",channel="defalut"):
        self.pub_key=""
        self.pri_key=""
        self.connect_domain = domain
        self.connect_port = port
        self.key=key
        self.channel=channel
    
    def start(self):
        conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn.connect((self.connect_domain, self.connect_port))
        self.conn=conn
        print('Connect succeed...')
        t = threading.Thread(target=self.read_thread, args=(conn,))
        t.start()
        self.send_handle(conn)
        while True:
            input_result = input()
            if input_result:
                if input_result == "\q":
                    data = {"action": "quit"}
                else:
                    if self.pub_key:
                        random_key=get_random_bytes(16)
                        encrypt_key=RSAUtil().encrypt(self.pub_key,random_key)
                        encrypt_content=AESUtil(random_key).encryptByCTR(input_result)
                        encrypt_content['key']=encrypt_key
                        data = {"action": "transform", "data": encrypt_content}
                    else:
                        print('public key is None could not send message to server')
                        data=None
                if data:
                    json_str = json.dumps(data)
                    encrypt_str = AESUtil(self.key).encryptByECB(json_str)
                    try:
                        conn.send(bytes(encrypt_str+"\n", "utf-8"))

                        # quit the client
                        if input_result == "\q":
                            break
                    except Exception as e:
                        print('send data for server error >>{}'.format(e))
                        break
        conn.close()
        os._exit(0)

    def read_thread(self,conn):
        while True:
            result = conn.recv(2048)
            if result:
                result = self.decrypt_data(str(result, 'utf-8'))
                if result:
                    action = result.get('action')
                    if action:
                        if action == "handle":
                            self.action_hanlde(result)
                        if action == "transform":
                            self.action_transform(result)
                        if action == "notify":
                            self.action_notify(result)
    
    def action_notify(self,data:dict):
        print(data['data'])

    def action_transform(self,data: dict):
        encrypt_data = data['data']['data']
        nonce = data['data']['nonce']
        random_key = data['data']['key']
        real_key = RSAUtil().decrypt(self.pri_key, random_key)
        real_message = AESUtil(real_key).decryptByCTR(encrypt_data, nonce)
        print('[{} online]{} >>{}'.format(data['online'],data['from'],real_message))

    def action_hanlde(self,data: dict):
        self.pub_key = data.get('data').get('public_key')
        self.pri_key = data.get('data').get('private_key')

    def decrypt_data(self,data: str):
        json_str = AESUtil(self.key).decryptByECB(data)
        try:
            return json.loads(json_str)
        except Exception as e:
            print('convert json error {}'.format(e))
            return None


    def send_handle(self,con):
        data = {
            "action": "handle",
            "channel":self.channel 
        }
        json_str = json.dumps(data)
        encrypt_str = AESUtil(self.key).encryptByECB(json_str)
        con.send(bytes(encrypt_str+"\n", "utf-8"))



if __name__ == "__main__":
    if  pathlib.Path('./config.json').exists():
        config_file=open('./config.json','r',encoding='utf8')
        json_str=config_file.read()
        try:
            json_obj=json.loads(json_str)
            DekuClient(domain=json_obj['server_address'],port=json_obj['port'],key=json_obj['password']).start()
        except Exception as e:
            print('Convert json failure {}'.format(e))
    else:
        print('The config.json is not exist in current dir')
