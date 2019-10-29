from socketserver import ThreadingTCPServer, StreamRequestHandler
from collections import defaultdict
import json
import os,pathlib
from cryptoUtil import AESUtil, RSAUtil

key = "我是传输的密码啦"
client_pool = defaultdict(list)  # store the clients
key_pool = defaultdict(dict)  # store the rsa keys


class ClientHandle(StreamRequestHandler):

    def handle(self):
        while True:
            data = self.rfile.readline()
            data = str(data, "utf-8")
            if data.endswith('\n'):
                data = data.replace("\n", "")
            data_obj = self.decrypt_data(data)
            if data_obj:
                # handle logic
                print('receive message from client {}'.format(data_obj))
                action = data_obj.get('action')
                if action:
                    if action == "handle":
                        self.action_handle(data_obj)
                    elif action == "transform":
                        self.action_transform(data_obj)
                    elif action == "quit":
                        break
            else:
                # quit the while loop when data dict is None ,it auto close the socket connection
                break

    def action_transform(self, data: dict):
        message = data['data']

        if self.channel:
            self._send_all_by_channel(AESUtil(key).encryptByECB(json.dumps({"action": "transform",
             "data": message,
             "from":"{}".format(self.client_address),
             "online":"{}".format(len(client_pool[self.channel]))})))

    def action_handle(self, data: dict):
        channel = data['channel']
        if channel:
            # append client to client pool
            self.channel = channel
            client_pool[channel].append(self)

            # send ras key for client
            self._send_keys()

            # notify other client the new client joined
            self._send_all_by_channel(AESUtil(key).encryptByECB(json.dumps(
                {"action": "notify", "data": "{} join the chatroom!!!".format(self.client_address)})))

    def _send_all_by_channel(self, message: str):
        clients = client_pool[self.channel]
        if len(clients) > 0:
            for client in clients:
                if client is not self:
                    try:
                        client.wfile.write(
                            bytes(message, 'utf8'))
                    except Exception as e:
                        print('send message for client {} error >>{}'.format(
                            client.client_address, e))
                        client.finish()

    def decrypt_data(self, data: str):
        if data:
            json_str = AESUtil(key).decryptByECB(data)
            try:
                return json.loads(json_str)
            except Exception as e:
                print('Json loads with exception {}'.format(e))
                return None
        else:
            print('The data is None when decrypt')
            return None

    def finish(self):
        print('{} client is closed!'.format(self.client_address))

        if  hasattr(self,"channel") and self.channel:
            # remove client from client pool if it exist
            if self in client_pool[self.channel]:
                client_pool[self.channel].remove(self)

            # notify leave message
            self._send_all_by_channel(AESUtil(key).encryptByECB(json.dumps(
                {"action": "notify", "data": "{} leave the chatroom.".format(self.client_address)})))

            #remove ras key if the channel do not have any client
            if len(client_pool[self.channel])==0:
                del key_pool[self.channel] 
                print('The rsa key for channel {} has been removed.'.format(self.channel))

    # send rsa keys for client
    def _send_keys(self):
        keys = key_pool[self.channel]
        if keys:
            json_str = json.dumps({"action": "handle", "data": keys})
            encrypt_data = AESUtil(key).encryptByECB(json_str)
            try:
                self.wfile.write(bytes(encrypt_data, 'utf8'))
            except Exception as e:
                print('send ras keys failure {}'.format(e))
                self.finish()
        else:
            genarate_keys = RSAUtil().createKey()
            key_pool[self.channel] = genarate_keys
            self._send_keys()


if __name__ == "__main__":
    if  pathlib.Path('./config.json').exists():
        config_file=open('./config.json','r',encoding='utf8')
        json_str=config_file.read()
        try:
            json_obj=json.loads(json_str)
            port=json_obj['port']
            key=json_obj['password']

            server = ThreadingTCPServer(("0.0.0.0", port), ClientHandle)
            print('server is run at 0.0.0.0:{port} port')
            server.serve_forever()
        except Exception as e:
            print('Convert json failure {}'.format(e))
    else:
        print('The config.json is not exist in current dir')

