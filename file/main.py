from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
import os
import subprocess
import sqlite3
import requests  

app = Flask(__name__)
app.secret_key = "123"

con = sqlite3.connect("database.db")
con.execute("create table if not exists custom(pid integer primary key,name text,mail text)")
con.close()
values = []



@app.route('/')
def index1():
    return render_template('index1.html')

@app.route('/login', methods=["GET", "POST"])
def login():
    if request.method == 'POST':
        try:
            name = request.form['name']
            password = request.form['password']
            con = sqlite3.connect("database.db")
            con.row_factory = sqlite3.Row
            cur = con.cursor()
            cur.execute("select * from custom where name=? and mail=?", (name, password))
            data = cur.fetchone()

            if data:
                session["name"] = data["name"]
                session["mail"] = data["mail"]
                return redirect(url_for("index"))
            else:
                flash("Username and password Mismatch", "danger")

        except Exception as e:
            print(f"Error: {str(e)}")
            flash("Check Your Name And Password")

    return redirect(url_for("index1"))

@app.route('/register', methods=['GET','POST'])
def register():
    if request.method=='POST':
        try:
            name=request.form['name']
            mail=request.form['mail']
            con=sqlite3.connect("database.db")
            cur=con.cursor()
            cur.execute("insert into custom(name,mail)values(?,?)",(name,mail))
            con.commit()
            flash("Record Added Successfully","success")
        except:
            flash("Error in Insert Operation","danger")
        finally:
            return redirect(url_for("index1"))
            con.close()

    return render_template('register.html')

@app.route('/index')
def index():
    return render_template('index.html')


def is_fake_filepath(file_path):
    # Check if the file path exists
    if not os.path.exists(file_path):
        return True  # Return True if the file path does not exist
    
    # Add more checks if needed
    
    return False  # Return False if the file path exists



@app.route('/classify_pe', methods=['POST'])
def classify_pe():
    file = request.form['file']
    if is_fake_filepath(file):
        return jsonify({'status': 'error', 'message': 'Fake filepath detected.'})
    else:
        output = subprocess.getoutput("python3 Extract/PE_main.py {}".format(file))
        return render_template('result.html', result=output)

    

def check_url():
    url = request.form['url']
    result = check_fake_url(url)
    return render_template('result.html', url=url, result=result)

@app.route('/classify_url', methods=['POST'])
def classify_url():
    try:
        url = request.form['url']
        response = requests.get(url)
        if response.status_code == 200:
            return 'real '
        else:
            return 'Fake'
    except requests.exceptions.RequestException:
        return 'Fake'



@app.route('/result')
def result():
    result_data = "Sample result data"  # Replace this with your actual result data
    return render_template('result.html', result=result_data)

@app.route('/exit', methods=['POST'])
def exit():
    os.system('exit')
    return jsonify({'status': 'success', 'message': 'Exiting...'})

if __name__ == "__main__":
    app.run(debug=False, port=500)
