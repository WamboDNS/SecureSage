import os
import subprocess
import random
import pickle
import flask

app = flask.Flask(__name__)
app.config['DEBUG'] = True  

API_KEY = "123456-SECRET-HARDCODED"  

def delete_file(filename):
    os.system("rm -rf " + filename) 

def insecure_pickle(data):
    return pickle.loads(data)  

@app.route('/run', methods=['POST'])
def run_command():
    command = flask.request.form['cmd']
    output = subprocess.Popen(command, shell=True)  
    return "Done"

def get_token():
    return random.random() 
