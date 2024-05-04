from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_cors import CORS
import os
import sys
import array
import math
import pickle
import joblib
import pandas as pd
import numpy as np
import random
import pefile
import subprocess
import sqlite3


app = Flask(__name__)
app.secret_key = "123"

CORS(app)



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


# For calculating the entropy
def get_entropy(data):
    if len(data) == 0:
        return 0.0
    occurrences = array.array('L', [0] * 256)
    for x in data:
        occurrences[x if isinstance(x, int) else ord(x)] += 1

    entropy = 0
    for x in occurrences:
        if x:
            p_x = float(x) / len(data)
            entropy -= p_x * math.log(p_x, 2)

    return entropy

# For extracting the resources part
def get_resources(pe):
    """Extract resources: [entropy, size]"""
    resources = []
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        try:
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if hasattr(resource_type, 'directory'):
                    for resource_id in resource_type.directory.entries:
                        if hasattr(resource_id, 'directory'):
                            for resource_lang in resource_id.directory.entries:
                                data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                                size = resource_lang.data.struct.Size
                                entropy = get_entropy(data)

                                resources.append([entropy, size])
        except Exception as e:
            return resources
    return resources

# For getting the version information
def get_version_info(pe):
    """Return version infos"""
    res = {}
    for fileinfo in pe.FileInfo:
        if fileinfo.Key == 'StringFileInfo':
            for st in fileinfo.StringTable:
                for entry in st.entries.items():
                    res[entry[0]] = entry[1]
        if fileinfo.Key == 'VarFileInfo':
            for var in fileinfo.Var:
                res[var.entry.items()[0][0]] = var.entry.items()[0][1]
    if hasattr(pe, 'VS_FIXEDFILEINFO'):
        res['flags'] = pe.VS_FIXEDFILEINFO.FileFlags
        res['os'] = pe.VS_FIXEDFILEINFO.FileOS
        res['type'] = pe.VS_FIXEDFILEINFO.FileType
        res['file_version'] = pe.VS_FIXEDFILEINFO.FileVersionLS
        res['product_version'] = pe.VS_FIXEDFILEINFO.ProductVersionLS
        res['signature'] = pe.VS_FIXEDFILEINFO.Signature
        res['struct_version'] = pe.VS_FIXEDFILEINFO.StrucVersion
    return res

# Extract the info for a given file using pefile
def extract_infos(pe_file_path):
    res = {}
    pe = pefile.PE(pe_file_path)
    res['Machine'] = pe.FILE_HEADER.Machine
    res['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
    res['Characteristics'] = pe.FILE_HEADER.Characteristics
    res['MajorLinkerVersion'] = pe.OPTIONAL_HEADER.MajorLinkerVersion
    res['MinorLinkerVersion'] = pe.OPTIONAL_HEADER.MinorLinkerVersion
    res['SizeOfCode'] = pe.OPTIONAL_HEADER.SizeOfCode
    res['SizeOfInitializedData'] = pe.OPTIONAL_HEADER.SizeOfInitializedData
    res['SizeOfUninitializedData'] = pe.OPTIONAL_HEADER.SizeOfUninitializedData
    res['AddressOfEntryPoint'] = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    res['BaseOfCode'] = pe.OPTIONAL_HEADER.BaseOfCode
    try:
        res['BaseOfData'] = pe.OPTIONAL_HEADER.BaseOfData
    except AttributeError:
        res['BaseOfData'] = 0
    res['ImageBase'] = pe.OPTIONAL_HEADER.ImageBase
    res['SectionAlignment'] = pe.OPTIONAL_HEADER.SectionAlignment
    res['FileAlignment'] = pe.OPTIONAL_HEADER.FileAlignment
    res['MajorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MajorOperatingSystemVersion
    res['MinorOperatingSystemVersion'] = pe.OPTIONAL_HEADER.MinorOperatingSystemVersion
    res['MajorImageVersion'] = pe.OPTIONAL_HEADER.MajorImageVersion
    res['MinorImageVersion'] = pe.OPTIONAL_HEADER.MinorImageVersion
    res['MajorSubsystemVersion'] = pe.OPTIONAL_HEADER.MajorSubsystemVersion
    res['MinorSubsystemVersion'] = pe.OPTIONAL_HEADER.MinorSubsystemVersion
    res['SizeOfImage'] = pe.OPTIONAL_HEADER.SizeOfImage
    res['SizeOfHeaders'] = pe.OPTIONAL_HEADER.SizeOfHeaders
    res['CheckSum'] = pe.OPTIONAL_HEADER.CheckSum
    res['Subsystem'] = pe.OPTIONAL_HEADER.Subsystem
    res['DllCharacteristics'] = pe.OPTIONAL_HEADER.DllCharacteristics
    res['SizeOfStackReserve'] = pe.OPTIONAL_HEADER.SizeOfStackReserve
    res['SizeOfStackCommit'] = pe.OPTIONAL_HEADER.SizeOfStackCommit
    res['SizeOfHeapReserve'] = pe.OPTIONAL_HEADER.SizeOfHeapReserve
    res['SizeOfHeapCommit'] = pe.OPTIONAL_HEADER.SizeOfHeapCommit
    res['LoaderFlags'] = pe.OPTIONAL_HEADER.LoaderFlags
    res['NumberOfRvaAndSizes'] = pe.OPTIONAL_HEADER.NumberOfRvaAndSizes

    # Sections
    res['SectionsNb'] = len(pe.sections)
    entropy = list(map(lambda x: x.get_entropy(), pe.sections))
    res['SectionsMeanEntropy'] = sum(entropy) / float(len(entropy))
    res['SectionsMinEntropy'] = min(entropy)
    res['SectionsMaxEntropy'] = max(entropy)
    raw_sizes = list(map(lambda x: x.SizeOfRawData, pe.sections))
    res['SectionsMeanRawsize'] = sum(raw_sizes) / float(len(raw_sizes))
    res['SectionsMinRawsize'] = min(raw_sizes)
    res['SectionsMaxRawsize'] = max(raw_sizes)
    virtual_sizes = list(map(lambda x: x.Misc_VirtualSize, pe.sections))
    res['SectionsMeanVirtualsize'] = sum(virtual_sizes) / float(len(virtual_sizes))
    res['SectionsMinVirtualsize'] = min(virtual_sizes)
    res['SectionMaxVirtualsize'] = max(virtual_sizes)

    # Imports
    try:
        res['ImportsNbDLL'] = len(pe.DIRECTORY_ENTRY_IMPORT)
        imports = sum([x.imports for x in pe.DIRECTORY_ENTRY_IMPORT], [])
        res['ImportsNb'] = len(imports)
        res['ImportsNbOrdinal'] = 0
    except AttributeError:
        res['ImportsNbDLL'] = 0
        res['ImportsNb'] = 0
        res['ImportsNbOrdinal'] = 0

    # Exports
    try:
        res['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)
    except AttributeError:
        # No export
        res['ExportNb'] = 0
    # Resources
    resources = get_resources(pe)
    res['ResourcesNb'] = len(resources)
    if len(resources) > 0:
        entropy = list(map(lambda x: x[0], resources))
        res['ResourcesMeanEntropy'] = sum(entropy) / float(len(entropy))
        res['ResourcesMinEntropy'] = min(entropy)
        res['ResourcesMaxEntropy'] = max(entropy)
        sizes = list(map(lambda x: x[1], resources))
        res['ResourcesMeanSize'] = sum(sizes) / float(len(sizes))
        res['ResourcesMinSize'] = min(sizes)
        res['ResourcesMaxSize'] = max(sizes)
    else:
        res['ResourcesNb'] = 0
        res['ResourcesMeanEntropy'] = 0
        res['ResourcesMinEntropy'] = 0
        res['ResourcesMaxEntropy'] = 0
        res['ResourcesMeanSize'] = 0
        res['ResourcesMinSize'] = 0
        res['ResourcesMaxSize'] = 0

    # Load configuration size
    try:
        res['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size
    except AttributeError:
        res['LoadConfigurationSize'] = 0

    # Version configuration size
    try:
        version_infos = get_version_info(pe)
        res['VersionInformationSize'] = len(version_infos.keys())
    except AttributeError:
        res['VersionInformationSize'] = 0
    return res

def sanitization(web):
    web = web.lower()
    token = []
    dot_token_slash = []
    raw_slash = str(web).split('/')
    for i in raw_slash:
        raw1 = str(i).split('-')
        slash_token = []
        for j in range(0,len(raw1)):
            raw2 = str(raw1[j]).split('.')
            slash_token = slash_token + raw2
        dot_token_slash = dot_token_slash + raw1 + slash_token
    token = list(set(dot_token_slash)) 
    if 'com' in token:
        token.remove('com')
    return token


file_path_model = "E:/Gopal/Url & File path Malware/Classifier/Classifier.pkl"
file_path_vectorizer = "E:/Gopal/Url & File path Malware/Classifier/features.pkl"

with open('E:/Gopal/Url & File path Malware/Classifier/pickel_model.pkl', 'rb') as f1:  
    lgr = pickle.load(f1)

with open('E:/Gopal/Url & File path Malware/Classifier/pickel_vector.pkl', 'rb') as f2:  
    vectorizer = pickle.load(f2)


@app.route('/index')
def index():
    return render_template('index.html')

@app.route('/result', methods=['POST'])
def result():
    url = request.form['url']
    urls = [url]

    # Using whitelist filter as the model fails in many legit cases since the biggest problem is not finding the malicious urls but to segregate the good ones
    whitelist = ['hackthebox.eu','root-me.org','gmail.com']
    s_url = [i for i in urls if i not in whitelist]

    if not s_url:  # Check if s_url is empty
        return render_template('result.html', prediction1="Invalid URL")

    # Predicting
    x = vectorizer.transform(s_url)
    y_predict = lgr.predict(x)

    for site in whitelist:
        s_url.append(site)

    predict = list(y_predict)
    for j in range(0,len(whitelist)):
        predict.append('good')

    return render_template('result.html', prediction1=predict[0])



def is_real_filepath(filepath):
    # Check if the filepath exists in the system
    import os
    return os.path.exists(filepath)

@app.route('/detect', methods=['POST'])
def detect():
    prediction = None
    if request.method == 'POST':
        filepath = request.form['file_path']
        if is_real_filepath(filepath):
            prediction = "Real"
        else:
            prediction = "Fake"
    return render_template('result1.html', prediction=prediction)





        
if __name__ == '__main__':
    app.run(debug=False,port=300)
