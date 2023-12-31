from Crypto.Cipher import AES
import time
import os
#import cProfile
#import re


def aes_enc(text):

    key = os.urandom(16)
    #key = b"abcdefg12jkrmnow"
    
    start_time = time.perf_counter()
    cipher = AES.new(key, AES.MODE_ECB)
    msg = cipher.encrypt(text)
    print(f"encryption time : {(time.perf_counter() - start_time) * 1} milliseconds\nencryption throughput : {17875/(time.perf_counter() - start_time)} KiloBytes per millisecond")
    
    #print(type(msg))

    #print(msg)
    
    start_time = time.perf_counter()
    decipher = AES.new(key, AES.MODE_ECB)
    print(f"decryption time : {(time.perf_counter() - start_time) * 1} milliseconds")
    #print(decipher.decrypt(msg))

with open('10mb.txt', 'rb') as file:
    text = file.read()
#start_time = time.perf_counter()
aes_enc(text)
#print(time.perf_counter() - start_time)
#cProfile.run('re.compile("foo|bar")')