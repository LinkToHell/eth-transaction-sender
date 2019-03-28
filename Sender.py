import rlp
import sha3
import time
import bitcoin
import requests
import eth_utils
import eth_abi
from rlp.sedes import *


def PrivToAddr(PrivKey):
    return sha3.keccak_256(bytes.fromhex(bitcoin.privtopub(PrivKey)[2:])).digest()[-20:].hex()


class Tx(rlp.Serializable):
    fields = [
        ('Nonce', big_endian_int),
        ('GasPrice', big_endian_int),
        ('GasLimit', big_endian_int),
        ('To', binary),
        ('Value', big_endian_int),
        ('Data', binary),
        ('v', big_endian_int),
        ('r', big_endian_int),
        ('s', big_endian_int)
    ]

    def __init__(self, Nonce, GasPrice, GasLimit, To, Value, Key, Data=b'', APIKey='YourApiKeyToken'):
        super().__init__(Nonce, GasPrice, GasLimit, bytes.fromhex(eth_utils.remove_0x_prefix(To)), Value, Data, 0, 0, 0)
        self.Key = eth_utils.remove_0x_prefix(Key)
        self.APIKey = APIKey
        self.Addr = PrivToAddr(Key)
        self.HexTx = ''
        self.Hash = ''

    def SetNonceWithEtherscanAPI(self):
        ans = requests.get('https://api.etherscan.io/api?module=proxy&action=eth_getTransactionCount&address=' + self.Addr + '&tag=latest&apikey' + self.APIKey).json()['result']
        self.Nonce = int(ans, 16)
        return self.Nonce

    def SetGasPriceWithEtherscanAPI(self):
        ans = requests.get('https://api.etherscan.io/api?module=proxy&action=eth_gasPrice&apikey=' + self.APIKey).json()['result']
        self.GasPrice = int(ans, 16)
        return self.GasPrice

    def SetGasLimitWithEtherscanAPI(self):
        ans = requests.get('https://api.etherscan.io/api?module=proxy&action=eth_estimateGas&from=' + self.Addr + '&to=' + self.To.hex() + '&value=' + str(self.Value) + '&data=0x' + self.Data.hex() + '&apikey' + self.APIKey).json()['result']
        self.GasLimit = int(ans, 16)
        return self.GasLimit

    def SetAllWithEtherscanAPI(self):
        self.SetNonceWithEtherscanAPI()
        self.SetGasPriceWithEtherscanAPI()
        self.SetGasLimitWithEtherscanAPI()

    def Sign(self):
        data = rlp.encode(self, Tx.exclude(['v', 's', 'r']))
        hash = sha3.keccak_256(data).digest()
        self.v, self.r, self.s = bitcoin.ecdsa_raw_sign(hash, self.Key)
        self.HexTx = rlp.encode(self).hex()
        return self.HexTx

    def Send(self):
        ans = requests.post('https://api.etherscan.io/api?module=proxy&action=eth_sendRawTransaction&hex=' + self.HexTx + '&apikey=' + self.APIKey)
        if 'error' in ans.json().keys():
            return None
        self.Hash = ans.json()['result']
        return self.Hash

    def Check(self):
        ans = requests.get('https://api.etherscan.io/api?module=proxy&action=eth_getTransactionByHash&txhash=' + self.Hash + '&apikey=' + self.APIKey).json()
        if 'error' in ans.keys() or ans['result'] is None or ans['result']['blockNumber'] is None:
            return None
        else:
            return ans

    def FastBroadcast(self):
        self.SetAllWithEtherscanAPI()
        self.Sign()
        self.Send()


def GetBalance(Keys, APIKey='YourApiKeyToken'):
    addr = ""
    for key in Keys:
        addr += PrivToAddr(key)
        addr += ","
    addr = addr[:-1]
    ans = requests.get('https://api.etherscan.io/api?module=account&action=balancemulti&address=' + addr + '&tag=latest&apikey=' + APIKey).json()['result']
    return ans


def GetTokenBalance(ContractAddress, HolderAddress, APIKey='YourApiKeyToken'):
    ans = requests.get('https://api.etherscan.io/api?module=account&action=tokenbalance&contractaddress=' + ContractAddress + '&address=' + HolderAddress + '&tag=latest&apikey=' + APIKey).json()['result']
    ans = int(ans)
    return ans


def BuyEOS(Key, FinalAddr, APIKey='YourApiKeyToken'):
    addr = PrivToAddr(key)
    EOSSaleAddr = '0xd0a6E6C54DbC68Db5db3A091B171A77407Ff7ccf'
    EOSTokenAddr = '0x86Fa049857E0209aa7D9e616F7eb3b3B78ECfdb0'

    Day = int((time.time() - 1498914000) / 23 / 3600) + 1

    Timestamp = 1498914000 + 23 * 3600 * Day

    balance = requests.get('https://api.etherscan.io/api?module=account&action=balance&address=' + addr + '&tag=latest&apikey=' + APIKey).json()['result']

    print('Sending ETH to EOS contract')

    tx = Tx(0, int(60 * 10 ** 9), 0, EOSSaleAddr, int(balance) - int(0.01 * 10 ** 18), Key, APIKey=APIKey)
    tx.SetGasLimitWithEtherscanAPI()
    tx.SetNonceWithEtherscanAPI()
    tx.Sign()
    tx.Send()

    print("Pending...")

    while True:
        time.sleep(1)
        check = tx.Check()
        if check != None:
            print(int(check['result']['blockNumber'], 16))
            break

    print('Done!')

    while True:
        if time.time() - 10 > Timestamp:
            break
        time.sleep(1)

    print('Claiming EOS from contract')

    tx = Tx(0, int(21 * 10 ** 9), 100000, EOSSaleAddr, 0, Key, Data=bytes.fromhex('379607f5') + eth_abi.encode_abi(['uint256'], [Day]), APIKey=APIKey)
    tx.SetNonceWithEtherscanAPI()
    tx.Sign()
    tx.Send()

    print('Pending...')

    while True:
        time.sleep(1)
        check = tx.Check()
        if check != None:
            print(int(check['result']['blockNumber'], 16))
            break

    print('Done!')

    EOSnum = GetTokenBalance(EOSTokenAddr, addr, APIKey=APIKey)

    print('Sending', EOSnum, 'EOS to' + FinalAddr)

    tx = Tx(0, int(21 * 10 ** 9), 0, EOSTokenAddr, 0, Key, Data=bytes.fromhex('a9059cbb') + eth_abi.encode_abi(['address', 'uint256'], [FinalAddr, EOSnum]), APIKey=APIKey)
    tx.SetGasLimitWithEtherscanAPI()
    tx.SetNonceWithEtherscanAPI()
    tx.Sign()
    tx.Send()

    print('Pending...')

    while True:
        time.sleep(1)
        check = tx.Check()
        if check != None:
            print(int(check['result']['blockNumber'], 16))
            break

    print('Done!')
