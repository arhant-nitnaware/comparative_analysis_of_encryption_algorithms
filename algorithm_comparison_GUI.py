import PySimpleGUI as gui

from Crypto.Cipher import AES, DES3, Blowfish
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util import Padding
import time
import os
import sys


#import cProfile
#import re

def dependencies():
    os.system('pip install pycryptodome')
    os.system('pip install PySimpleGUI')


def aes_enc(text):
    print("AES")
    st = time.perf_counter()
    key = os.urandom(16)
    cipher_enc = AES.new(key, AES.MODE_ECB) 
    padded_text = Padding.pad(text.encode(), AES.block_size)
    encrypted_text = cipher_enc.encrypt(padded_text)
    en_time = time.perf_counter() - st
    
    st = time.perf_counter()
    cipher_dec = AES.new(key, AES.MODE_ECB)
    decrypted_padded_text = cipher_dec.decrypt(encrypted_text)
    decrypted_text = Padding.unpad(decrypted_padded_text, AES.block_size)
    de_time = time.perf_counter() - st

    return en_time, de_time


def tdes_enc(text):
    print("TDES")
    st = time.perf_counter()
    key = DES3.adjust_key_parity(os.urandom(24))
    cipher_enc = DES3.new(key, DES3.MODE_ECB)
    padded_text = Padding.pad(text.encode(), DES3.block_size)
    encrypted_text = cipher_enc.encrypt(padded_text)
    en_time = time.perf_counter() -st

    st = time.perf_counter()
    cipher_dec = DES3.new(key, DES3.MODE_ECB)
    decrypted_padded_text = cipher_dec.decrypt(encrypted_text)
    decrypted_text = Padding.unpad(decrypted_padded_text, DES3.block_size)
    de_time = time.perf_counter() - st

    return en_time, de_time


def bf_enc(text):
    print("BF")
    st = time.perf_counter()
    key = os.urandom(16)
    cipher_enc = Blowfish.new(key, Blowfish.MODE_ECB)
    padded_text = Padding.pad(text.encode(), Blowfish.block_size)
    encrypted_text = cipher_enc.encrypt(padded_text)
    en_time = time.perf_counter() - st

    st = time.perf_counter()
    cipher_dec = Blowfish.new(key, Blowfish.MODE_ECB)
    decrypted_padded_text = cipher_dec.decrypt(encrypted_text)
    decrypted_text = Padding.unpad(decrypted_padded_text, Blowfish.block_size)
    de_time = time.perf_counter() - st

    return en_time, de_time


def rsa_enc(text):
    print("RSA")
    
    #generate RSA keys
    rsa_key = RSA.generate(int(2048))
    private_key = rsa_key.exportKey('PEM')
    public_key = rsa_key.public_key().export_key('PEM')

    st = time.perf_counter()
    #encrypt the message
    public_key_obj = RSA.import_key(public_key)
    cipher_encrypt = PKCS1_OAEP.new(public_key_obj)
    encrypted_text = cipher_encrypt.encrypt(text.encode())
    encrypted_hex = (encrypted_text)
    en_time = time.perf_counter() - st

    #decrypt the message
    st = time.perf_counter()
    private_key_obj = RSA.import_key(private_key)
    cipher_decrypt = PKCS1_OAEP.new(private_key_obj)
    decrypted_text = cipher_decrypt.decrypt(encrypted_text)
    de_time = time.perf_counter() - st

    return en_time, de_time


def choose_file(input):
    if input == 1:
        file = "5mb.txt"
        with open(file, 'r') as text:
            data = text.read()
            return data
    elif input == 2:
        file = "10mb.txt"
        with open(file, 'r') as text:
            data = text.read()
            return data
    elif input == 3:
        file = "mnist_test.txt"
        with open(file, 'r') as text:
            data = text.read()
            return data
    else:
        exit("u_ERROR - choose_file() 'input' param out of bounds : choose from 1,2,3")
    

def make_gui():
    #set the theme
    gui.theme("DarkTanBlue")

    #algorithm radio layout (left)(first) andn its frame
    algo_layout = [[gui.Radio( text="AES-128",group_id=1, default=True, size=(100,1), pad=((5,5),(8,8)), font="bold", tooltip="Advanced Encryption System - 128", enable_events=True)],
                    [gui.Radio(text="3DES",group_id=1, size=(100,1), pad=((5,5),(8,8)), font="bold", tooltip="Data Encryption Standard", enable_events=True)],
                    [gui.Radio(text="RSA",group_id=1, size=(100,1), pad=((5,5),(8,8)), font="bold", tooltip="Rivest-Shamir-Adleman Algorithm", enable_events=True)],
                    [gui.Radio(text="BlowFish",group_id=1, size=(100,1), pad=((5,5),(8,8)), font="bold", tooltip="BlowFish Cipher", enable_events=True)]
                    ] 
    algo_frame = gui.Frame(layout=algo_layout, title="Select Algorithm",font="bold 13", size=(150,220))

    #input layout (middle) (second) and its frame
    input_layout = [[gui.Input("",expand_y = False, size=(40, 50), tooltip="enter text", text_color="black", font="bold", enable_events=True, key="_U_INP_")],
                    [gui.Radio(text="User Input", group_id=2, size=(100,1), font="bold", default=True, key="_RD_U_INP_", enable_events=True)],
                    [gui.Radio(text="5MB file", group_id=2, size=(100,1), font="bold", enable_events=True, key = "_RD_5MB_")],
                    [gui.Radio(text="10MB file", group_id=2, size=(100,1), font="bold", enable_events=True, key = "_RD_10MB_")],
                    [gui.Radio(text="17.4MB file", group_id=2, size=(100,1), font="bold", enable_events=True, key = "_RD_17.4MB_")]
                    ]
    input_frame = gui.Frame(layout=input_layout, title="Input text to encrypt", font="bold 13", size=(250,220))

    #result layout ()
    result_layout = [[gui.Text(f"Encryption Time: ", pad = ((5,3), (20,5)), font="bold", key="_RES_EN_")],
                    [gui.Text(f"Decryption Time: ", pad = ((5,3), (10,5)), font="bold", key="_RES_DE_")],
                    [gui.Text(f"Encryption Throughput: ", pad = ((5,3), (10,5)), font="bold", key="_RES_EN_TP_")],
                    [gui.Text(f"Decryption Throughput: ", pad = ((5,3), (10,5)), font="bold", key="_RES_DE_TP_")]
                    ]
    result_frame = gui.Frame(layout=result_layout, title="Result", size=(800,220), font="bold")

    layout=[
            [gui.Text("Comparitive Analysis of Algorithms", expand_x=True, justification="center", font=("Arial Bold", 17), pad=((0,0),(10,10)), relief="sunken")],
            [gui.Column(layout=[[algo_frame]]), gui.Column(layout=[[input_frame]]),  gui.Button(button_text="Encrypt", size=(15,2), font="bold",border_width=5, disabled=True, enable_events=True, key="_EN_BT_"), gui.Column(layout=[[result_frame]])]
            ]

    #creates window
    root = gui.Window("Minor Project-Comapartitive study of Encryption Algorithms ", layout, size=(1200,300), no_titlebar=False, grab_anywhere=True)

    #event loop
    while(True):
        
        #read wtf in happening in he window
        event, values = root.read()
        print(event, values)

        if event == "OK" or event == gui.WIN_CLOSED:
            break
        
        if values["_U_INP_"] == "" and values["_RD_U_INP_"] == True:
            root["_EN_BT_"].update(disabled=True)     
        else:
            root["_EN_BT_"].update(disabled=False)
        
        if(values["_RD_U_INP_"] != True):
            root["_EN_BT_"].update(disabled=False)

        if(values[2] == True and not(values["_RD_U_INP_"] == True)):
            root["_EN_BT_"].update(disabled=True)

        #time functions
        if event == "_EN_BT_":
            if values["_RD_U_INP_"] == True:#for user input 
                ui = "_U_INP_"
                if(values[0] == True):#for AES
                    en, de = aes_enc(values[ui])
                    root["_RES_EN_"].update(f"Encryption Time: {en} milliseconds")
                    root["_RES_DE_"].update(f"Decryption Time: {de} milliseconds")
                    root["_RES_EN_TP_"].update(f"Encryption Throughput: {(sys.getsizeof(values[ui])) * 0.001 / en} kb/ms")
                    root["_RES_DE_TP_"].update(f"Decryption Throughput: {(sys.getsizeof(values[ui])) * 0.001 / de} kb/ms")
                if(values[1] == True):#for 3des
                    en, de = tdes_enc(values[ui])
                    root["_RES_EN_"].update(f"Encryption Time: {en} milliseconds")
                    root["_RES_DE_"].update(f"Decryption Time: {de} milliseconds")
                    root["_RES_EN_TP_"].update(f"Encryption Throughput: {(sys.getsizeof(values[ui])) * 0.001 / en} kb/ms")
                    root["_RES_DE_TP_"].update(f"Decryption Throughput: {(sys.getsizeof(values[ui])) * 0.001 / de} kb/ms")
                if(values[2] == True):#for rsa
                    en, de = rsa_enc(values[ui])
                    root["_RES_EN_"].update(f"Encryption Time: {en} milliseconds")
                    root["_RES_DE_"].update(f"Decryption Time: {de} milliseconds")
                    root["_RES_EN_TP_"].update(f"Encryption Throughput: {(sys.getsizeof(values[ui])) * 0.001 / en} kb/ms")
                    root["_RES_DE_TP_"].update(f"Decryption Throughput: {(sys.getsizeof(values[ui])) * 0.001 / de} kb/ms")
                if(values[3] == True):#for bf
                    en, de = bf_enc(values[ui])
                    root["_RES_EN_"].update(f"Encryption Time: {en} milliseconds")
                    root["_RES_DE_"].update(f"Decryption Time: {de} milliseconds")
                    root["_RES_EN_TP_"].update(f"Encryption Throughput: {(sys.getsizeof(values[ui])) * 0.001 / en} kb/ms")
                    root["_RES_DE_TP_"].update(f"Decryption Throughput: {(sys.getsizeof(values[ui])) * 0.001 / de} kb/ms")
            if values["_RD_5MB_"] == True:#for 5mb file
                if(values[0] == True):#for AES
                    en, de = aes_enc(choose_file(1))
                    root["_RES_EN_"].update(f"Encryption Time: {en} milliseconds")
                    root["_RES_DE_"].update(f"Decryption Time: {de} milliseconds")
                    root["_RES_EN_TP_"].update(f"Encryption Throughput: {(sys.getsizeof(choose_file(1))) * 0.001 / en} kb/ms")
                    root["_RES_DE_TP_"].update(f"Decryption Throughput: {(sys.getsizeof(choose_file(1))) * 0.001 / de} kb/ms")
                if(values[1] == True):#for 3DES
                    en, de = tdes_enc(choose_file(1))
                    root["_RES_EN_"].update(f"Encryption Time: {en} milliseconds")
                    root["_RES_DE_"].update(f"Decryption Time: {de} milliseconds")
                    root["_RES_EN_TP_"].update(f"Encryption Throughput: {(sys.getsizeof(choose_file(1))) * 0.001 / en} kb/ms")
                    root["_RES_DE_TP_"].update(f"Decryption Throughput: {(sys.getsizeof(choose_file(1))) * 0.001 / de} kb/ms")
                if(values[2] == True):#for RSA
                    en, de = rsa_enc(choose_file(1))
                    root["_RES_EN_"].update(f"Encryption Time: {en} milliseconds")
                    root["_RES_DE_"].update(f"Decryption Time: {de} milliseconds")
                    root["_RES_EN_TP_"].update(f"Encryption Throughput: {(sys.getsizeof(choose_file(1))) * 0.001 / en} kb/ms")
                    root["_RES_DE_TP_"].update(f"Decryption Throughput: {(sys.getsizeof(choose_file(1))) * 0.001 / de} kb/ms")
                if(values[3] == True):#for BF
                    en, de = bf_enc(choose_file(1))
                    root["_RES_EN_"].update(f"Encryption Time: {en} milliseconds")
                    root["_RES_DE_"].update(f"Decryption Time: {de} milliseconds")
                    root["_RES_EN_TP_"].update(f"Encryption Throughput: {(sys.getsizeof(choose_file(1))) * 0.001 / en} kb/ms")
                    root["_RES_DE_TP_"].update(f"Decryption Throughput: {(sys.getsizeof(choose_file(1))) * 0.001 / de} kb/ms")
            if values["_RD_10MB_"] == True:#for 10mb file
                if(values[0] == True):#for AES
                    en, de = aes_enc(choose_file(2))
                    root["_RES_EN_"].update(f"Encryption Time: {en} milliseconds")
                    root["_RES_DE_"].update(f"Decryption Time: {de} milliseconds")
                    root["_RES_EN_TP_"].update(f"Encryption Throughput: {(sys.getsizeof(choose_file(2))) * 0.001 / en} kb/ms")
                    root["_RES_DE_TP_"].update(f"Decryption Throughput: {(sys.getsizeof(choose_file(2))) * 0.001 / de} kb/ms")
                if(values[1] == True):#for 3DES
                    en, de = tdes_enc(choose_file(2))
                    root["_RES_EN_"].update(f"Encryption Time: {en} milliseconds")
                    root["_RES_DE_"].update(f"Decryption Time: {de} milliseconds")
                    root["_RES_EN_TP_"].update(f"Encryption Throughput: {(sys.getsizeof(choose_file(2))) * 0.001 / en} kb/ms")
                    root["_RES_DE_TP_"].update(f"Decryption Throughput: {(sys.getsizeof(choose_file(2))) * 0.001 / de} kb/ms")
                if(values[2] == True):#for RSA
                    en, de = rsa_enc(choose_file(2))
                    root["_RES_EN_"].update(f"Encryption Time: {en} milliseconds")
                    root["_RES_DE_"].update(f"Decryption Time: {de} milliseconds")
                    root["_RES_EN_TP_"].update(f"Encryption Throughput: {(sys.getsizeof(choose_file(2))) * 0.001 / en} kb/ms")
                    root["_RES_DE_TP_"].update(f"Decryption Throughput: {(sys.getsizeof(choose_file(2))) * 0.001 / de} kb/ms")
                if(values[3] == True):#for BF
                    en, de = bf_enc(choose_file(2))
                    root["_RES_EN_"].update(f"Encryption Time: {en} milliseconds")
                    root["_RES_DE_"].update(f"Decryption Time: {de} milliseconds")
                    root["_RES_EN_TP_"].update(f"Encryption Throughput: {(sys.getsizeof(choose_file(2))) * 0.001 / en} kb/ms")
                    root["_RES_DE_TP_"].update(f"Decryption Throughput: {(sys.getsizeof(choose_file(2))) * 0.001 / de} kb/ms")
            if values["_RD_17.4MB_"] == True:#for 17mb file
                if(values[0] == True):#for AES
                    en, de = aes_enc(choose_file(3))
                    root["_RES_EN_"].update(f"Encryption Time: {en} milliseconds")
                    root["_RES_DE_"].update(f"Decryption Time: {de} milliseconds")
                    root["_RES_EN_TP_"].update(f"Encryption Throughput: {(sys.getsizeof(choose_file(3))) * 0.001 / en} kb/ms")
                    root["_RES_DE_TP_"].update(f"Decryption Throughput: {(sys.getsizeof(choose_file(3))) * 0.001 / de} kb/ms")
                if(values[1] == True):#for 3DES
                    en, de = tdes_enc(choose_file(3))
                    root["_RES_EN_"].update(f"Encryption Time: {en} milliseconds")
                    root["_RES_DE_"].update(f"Decryption Time: {de} milliseconds")
                    root["_RES_EN_TP_"].update(f"Encryption Throughput: {(sys.getsizeof(choose_file(3))) * 0.001 / en} kb/ms")
                    root["_RES_DE_TP_"].update(f"Decryption Throughput: {(sys.getsizeof(choose_file(3))) * 0.001 / de} kb/ms")
                if(values[2] == True):#for RSA
                    en, de = rsa_enc(choose_file(3))
                    root["_RES_EN_"].update(f"Encryption Time: {en} milliseconds")
                    root["_RES_DE_"].update(f"Decryption Time: {de} milliseconds")
                    root["_RES_EN_TP_"].update(f"Encryption Throughput: {(sys.getsizeof(choose_file(3))) * 0.001 / en} kb/ms")
                    root["_RES_DE_TP_"].update(f"Decryption Throughput: {(sys.getsizeof(choose_file(3))) * 0.001 / de} kb/ms")
                if(values[3] == True):#for BF
                    en, de = bf_enc(choose_file(3))
                    root["_RES_EN_"].update(f"Encryption Time: {en} milliseconds")
                    root["_RES_DE_"].update(f"Decryption Time: {de} milliseconds")
                    root["_RES_EN_TP_"].update(f"Encryption Throughput: {(sys.getsizeof(choose_file(3))) * 0.001 / en} kb/ms")
                    root["_RES_DE_TP_"].update(f"Decryption Throughput: {(sys.getsizeof(choose_file(3))) * 0.001 / de} kb/ms")

    root.close()


#==========MAIN===========#
make_gui()