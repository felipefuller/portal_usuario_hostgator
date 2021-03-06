from flask import Flask, render_template, flash, redirect, abort, url_for, session, request, logging, jsonify, send_from_directory
#from data import Articles
from flask_mysqldb import MySQL
from flask_wtf import RecaptchaField
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, SubmitField, IntegerField
from wtforms.fields.html5 import DateField
from passlib.hash import sha256_crypt
from functools import wraps
from werkzeug.utils import secure_filename
import os
import requests
from password_strength import PasswordPolicy
import json

app = Flask(__name__)

UPLOAD_FOLDER = './uploads'
ALLOWED_EXTENSIONS = {'pdf', 'doc', 'docx'}
ALLOWED_EXTENSIONS_AVATAR = {'jpeg', 'jpg', 'png'}
API_KEY = "KTXvLBD7TvoBjVxp9iRyJcJLgWeM3mkS"

# Config MySQL 162.214.68.240
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'usuarios_puser19'
app.config['MYSQL_PASSWORD'] = 'TalooUser_2019.'
app.config['MYSQL_DB'] = 'usuarios_puser'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
app.config['SECRET_KEY'] = '05686F1CD04C96751262607325F7BA48B3561E566D95ACD2B4E0F5045F5D8DD1'

app.config['RECAPTCHA_USE_SSL']= False
app.config['RECAPTCHA_PUBLIC_KEY']='6LeFLrwUAAAAAHkPL4QeGZGHHFYiMm78MhO0Fe3C'
app.config['RECAPTCHA_PRIVATE_KEY']='6LeFLrwUAAAAANL76lW5MN7fqWD_xsT29TOCChZU'
app.config['RECAPTCHA_OPTIONS']= {'theme':'black'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

API_KEY_JOBS = "RWDvLBD7TvoDaReNDiRyJcJLgWeM3mkS"
API_URL = 'https://empresas.taloo.cl/api/1.0'

# init MYSQL
mysql = MySQL(app)
#Articles = Articles()

@app.errorhandler(404)
def page_not_found(e):
    return redirect('/dashboard'), 404
    
# Index
@app.route('/')
def index():
    return render_template('home.html')


# About
@app.route('/about')
def about():
    return render_template('about.html')


# Articles
@app.route('/articles')
def articles():
    # Create cursor
    cur = mysql.connection.cursor()

    # Get articles
    result = cur.execute("SELECT * FROM articles")

    articles = cur.fetchall()

    if result > 0:
        return render_template('articles.html', articles=articles)
    else:
        msg = 'No Articles Found'
        return render_template('articles.html', msg=msg)
    # Close connection
    cur.close()


#Single Article
@app.route('/article/<string:id>/')
def article(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Get article
    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])

    article = cur.fetchone()

    return render_template('article.html', article=article)


# Register Form Class
class RegisterForm(Form):
    name = StringField('Name', [validators.Length(min=1, max=50)])
    lastname = StringField('Apellido', [validators.Length(min=1, max=50)])
    username = StringField('Username', [validators.Length(min=4, max=25)])
    email = StringField('Email', [validators.Length(min=6, max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords do not match')
    ])
    confirm = PasswordField('Confirm Password')
    recaptcha = RecaptchaField()


# User Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        name = form.name.data
        lastname = form.lastname.data
        email = form.email.data
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))

        policy = PasswordPolicy.from_names(
            length=8,  # min length: 8
            uppercase=1,  # need min. 2 uppercase letters
            numbers=2,  # need min. 2 digits
            special=0,  # need min. 2 special characters
            nonletters=0,  # need min. 2 non-letter characters (digits, specials, anything)
        )

        validate_password = policy.test(form.password.data)

        # Create cursor
        cur = mysql.connection.cursor()

        user_validator = cur.execute("SELECT username FROM users WHERE username = %s", [username])

        if user_validator == 0 and len(validate_password) == 0:
            # Execute query
            cur.execute("INSERT INTO users(name, lastname, email, username, password) VALUES(%s, %s, %s, %s, %s)", (name, lastname, email, username, password))

            # Commit to DB
            mysql.connection.commit()

            # Close connection
            cur.close()

            flash('¡Ahora que estás registrado puedes ingresar!', 'success')

            return redirect(url_for('login'))
        else:
            if len(validate_password) != 0:
                error_password = "¡Contraseña muy débil, incluya una Mayúscula y al menos 2 números!"
            else:
                error_password = "None"
            if user_validator != 0:
                error_user = "¡Usuario o contraseña erronea!"
            else:
                error_user = "None"
            return render_template('register.html', form=form, error_user=error_user, error_password=error_password)
            # Close connection
            cur.close()
    return render_template('register.html', form=form)

class LoginForm(Form):
    
    username = StringField('Usuario', [validators.Length(min=3, max=25)])
    password = PasswordField('Password', [validators.DataRequired()])
    recaptcha = RecaptchaField()

# User login
@app.route('/login', methods=['GET', 'POST'])
def login():

    form = LoginForm(request.form)

    if request.method == 'POST' and form.validate():

        # Get Form Fields
        username = form.username.data
        password_candidate = form.password.data
        # Create cursor
        cur = mysql.connection.cursor()

        # Get user by username
        result = cur.execute("SELECT * FROM users WHERE username = %s", [username])

        if result > 0:
            # Get stored hash
            data = cur.fetchone()
            password = data['password']

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['username'] = username

                #flash('¡Bienvenido! Ahora podrás publicar todas tus ofertas 😁', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = '* ¡Usuario/Contraseña errone@, por favor intente denuevo!'
                return render_template('login.html', error=error, form=form)
            # Close connection
            cur.close()
        else:
            error = '¡Contraseña erronea, por favor intente denuevo!'
            return render_template('login.html', error=error, form=form)

    return render_template('login.html', form=form)

# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            #flash('No autorizado, por favor inicie a su perfil', 'danger')
            return redirect(url_for('login'))
    return wrap

##################################################
################## Starts API's ##################
##################################################

@app.route("/api/1.0/uploads")
def list_files():
    """Endpoint to list files on the server."""
    headers = request.headers
    auth = headers.get("X-Api-Key")
    if auth == API_KEY:
        files = []
        for filename in os.listdir(UPLOAD_FOLDER):
            path = os.path.join(UPLOAD_FOLDER, filename)
            if os.path.isfile(path):
                files.append(filename)
        return jsonify(files)
    else:
        return jsonify({"message": "ERROR: Unauthorized"}), 401

@app.route("/api/1.0/files/<path:path>")
def get_file(path):
    """Download a file."""
    headers = request.headers
    auth = headers.get("X-Api-Key")
    if auth == API_KEY:
        return send_from_directory(UPLOAD_FOLDER, path, as_attachment=True)
    else:
        return jsonify({"message": "ERROR: Unauthorized"}), 401

@app.route("/api/1.0/files/<filename>", methods=["POST"])
def post_file(filename):
    """Upload a file."""
    headers = request.headers
    auth = headers.get("X-Api-Key")
    if auth == API_KEY:
        if "/" in filename:
            # Return 400 BAD REQUEST
            abort(400, "no subdirectories directories allowed")

        with open(os.path.join(UPLOAD_FOLDER, filename), "wb") as fp:
            fp.write(request.data)

        # Return 201 CREATED
        return "", 201
    else:
        return jsonify({"message": "ERROR: Unauthorized"}), 401

@app.route("/api/1.0/db_us")
def list_files_db():
    headers = request.headers
    auth = headers.get("X-Api-Key")

    if auth == API_KEY:
        # Create cursor
        cur = mysql.connection.cursor()
        cur.execute("SELECT * FROM archivos")
        rows = cur.fetchall()
        #Close connection
        cur.close()
        resp = jsonify(rows)
        resp.status_code = 200
        return resp
    else:
        return jsonify({"message": "ERROR: Unauthorized"}), 401

@app.route("/api/1.0/soft_erase/<id>", methods=["PUT"])
def soft_erase(id):
    headers = request.headers
    auth = headers.get("X-Api-Key")

    if auth == API_KEY:
        number = int(id)
        # Create cursor
        cur = mysql.connection.cursor()
        cur.execute("UPDATE archivos SET erased=%s WHERE id=%s",(1, [number]))
        #Close connection
        cur.close()
        return jsonify({"message": "success"}), 200
    else:
        return jsonify({"message": "ERROR: Unauthorized"}), 401
####################################################

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    #flash('You are now logged out', 'success')
    return redirect(url_for('login'))


# User Update Class
class UserUpdate(Form):
    name = StringField('Nombre', [validators.Length(min=2, max=20)])
    lastname = StringField('Apellidos', [validators.Length(min=2, max=20)])
    email = StringField('Email', [validators.Email(message='Correo incorrecto, por favor revisar')])
    phone = StringField('Teléfono', [validators.Length(min=0, max=15)])
    birthdate = StringField('Fecha de nacimiento', [validators.Length(min=0, max=15)])
    #birthdate = DateField('Fecha de nacimiento', format='%d/%m/%Y')
    direccion = StringField('Dirección', [validators.Length(min=0, max=60)])
    country = StringField('País', [validators.Length(min=0, max=15)])
    comuna = StringField('Comuna', [validators.Length(min=0, max=15)])
    postal = StringField('Código postal', [validators.Length(min=0, max=10)])
    web = StringField('Página web', [validators.Length(min=0, max=60)])
    linkedin = StringField('LinkedIn', [validators.Length(min=0, max=60)])
    twitter = StringField('Twitter', [validators.Length(min=0, max=20)])
    submit_update = SubmitField('Actualizar')

# Upload CV Class
class UploadCv(Form):
    submit_upload = SubmitField('Subir')

# Upload Avatar Class
class UploadAvatar(Form):
    submit_avatar = SubmitField('Image')

# Dashboard
@app.route('/dashboard', methods=['GET', 'POST'])
@is_logged_in
def dashboard():
    
    form_cv = UploadCv(request.form)
    form_avatar = UploadAvatar(request.form)
    form = UserUpdate(request.form)

    cur = mysql.connection.cursor()
    cur.execute("SELECT * FROM users WHERE username = %s", [session['username']])
    user_name = cur.fetchone()
    cur.close()

    form.name.data = user_name['name']
    form.lastname.data = user_name['lastname']
    form.email.data = user_name['email']
    form.phone.data = user_name['phone']
    form.birthdate.data = user_name['birthdate']
    form.direccion.data = user_name['direccion']
    form.country.data = user_name['country']
    form.comuna.data = user_name['comuna']
    form.postal.data = user_name['postal']
    form.web.data = user_name['web']
    form.linkedin.data = user_name['linkedin']
    form.twitter.data = user_name['twitter']

    if request.method == 'POST' and form_cv.validate() and form_cv.submit_upload.data:

        # check if the post request has the file part
        if 'file' not in request.files:
            flash('¡Error subiendo, intente denuevo!')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No se seleccionó ningún archivo 😞')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], session['username'] + filename))
            # Create Cursor
            cur = mysql.connection.cursor()

            # Execute
            cur.execute("INSERT INTO archivos(nombre_usuario, archivo) VALUES(%s, %s)",(session['username'], session['username'] + filename))

            # Commit to DB
            mysql.connection.commit()

            #Close connection
            cur.close()
            flash('Archivo subido de manera exitosa 😊')
            return redirect('/dashboard')
        else:
            flash('Solo puedes subir archivos pdf, doc y docx 🙁')
            return redirect(request.url)

    if request.method == 'POST' and form_cv.validate() and form_avatar.submit_avatar.data:
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('¡Error subiendo, intente denuevo!')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No se seleccionó ningún archivo 😞')
            return redirect(request.url)
        if file and allowed_file_avatar(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], session['username'] + filename))
            # Create Cursor
            cur = mysql.connection.cursor()

            # Execute
            cur.execute("UPDATE users SET avatar=%s WHERE username=%s",('uploads/' + session['username'] + filename, session['username']))

            # Commit to DB
            mysql.connection.commit()

            #Close connection
            cur.close()
            flash('Archivo subido de manera exitosa 😊')
            return redirect('/dashboard')
        else:
            flash('Solo puedes subir archivos jpeg, jpg y png 🙁')
            return redirect(request.url)

    if request.method == 'POST' and form.validate() and form.submit_update.data:

        name = request.form['name']
        lastname = request.form['lastname']
        email = request.form['email']
        phone = request.form['phone']
        birthdate = request.form['birthdate']
        direccion = request.form['direccion']
        country = request.form['country']
        comuna = request.form['comuna']
        postal = request.form['postal']
        web = request.form['web']
        linkedin = request.form['linkedin']
        twitter = request.form['twitter']

        # Create Cursor
        cur = mysql.connection.cursor()
        # Execute
        cur.execute("UPDATE users SET name=%s, lastname=%s, email=%s, phone=%s, birthdate=%s, direccion=%s, country=%s, comuna=%s, postal=%s, web=%s, linkedin=%s, twitter=%s WHERE username=%s", (name, lastname, email, phone, birthdate, direccion, country, comuna, postal, web, linkedin, twitter, session['username']))
        # Commit to DB
        mysql.connection.commit()
        #Close connection
        cur.close()

        flash('¡Perfil actualizado!', 'success')

        return redirect(url_for('dashboard'))

    return render_template('dashboard.html', form_cv=form_cv, form=form, form_avatar=form_avatar, avatar_url=user_name['avatar'], user=user_name['name'], lastname=user_name['lastname'])

@app.route('/uploads/<path:filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)

# Article Form Class
class ArticleForm(Form):
    title = StringField('Title', [validators.Length(min=1, max=200)])
    body = TextAreaField('Body', [validators.Length(min=30)])

# Add Article
@app.route('/add_article', methods=['GET', 'POST'])
@is_logged_in
def add_article():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data

        # Create Cursor
        cur = mysql.connection.cursor()

        # Execute
        cur.execute("INSERT INTO articles(title, body, author) VALUES(%s, %s, %s)",(title, body, session['username']))

        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('Article Created', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_article.html', form=form)

# Upload files CV
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Upload image Avatar
def allowed_file_avatar(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS_AVATAR

# Edit Article
@app.route('/edit_article/<string:id>', methods=['GET', 'POST'])
@is_logged_in
def edit_article(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Get article by id
    result = cur.execute("SELECT * FROM articles WHERE id = %s", [id])

    article = cur.fetchone()
    cur.close()
    # Get form
    form = ArticleForm(request.form)

    # Populate article form fields
    form.title.data = article['title']
    form.body.data = article['body']

    if request.method == 'POST' and form.validate():
        title = request.form['title']
        body = request.form['body']

        # Create Cursor
        cur = mysql.connection.cursor()
        app.logger.info(title)
        # Execute
        cur.execute ("UPDATE articles SET title=%s, body=%s WHERE id=%s",(title, body, id))
        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('Article Updated', 'success')

        return redirect(url_for('dashboard'))

    return render_template('edit_article.html', form=form)

@is_logged_in
def myID():
    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM users WHERE username = %s", [session['username']])
    user_id = cur.fetchone()
    cur.close()
    return user_id

@is_logged_in
def addLikes(user_id, job_id):
     # Retrieve user data
    cur = mysql.connection.cursor()
    # Get user by username
    cur.execute("INSERT INTO follow_company(user_id, job_id) VALUES (%s, %s)", [user_id, job_id])
    mysql.connection.commit()
    cur.close()

@is_logged_in
def deleteLikes(job_id):
     # Retrieve user data
    cur = mysql.connection.cursor()
    # Get user by username
    cur.execute("DELETE FROM follow_company WHERE job_id = (%s)", [job_id])
    mysql.connection.commit()
    cur.close()

@is_logged_in
def listLikes():

    cur = mysql.connection.cursor()
    cur.execute("SELECT id FROM users WHERE username = %s", [session['username']])
    user_name = cur.fetchone()
    user_id = user_name['id']


    # Get user by username
    cur.execute("SELECT * FROM follow_company WHERE user_id = (%s)", [user_id])
    user = cur.fetchall()
    cur.close()
    return user

@app.route('/like', methods=['GET', 'POST'])
@is_logged_in
def like():

    if request.method == 'POST':
        job_id = request.form['id']

        # headers = {'X-Api-Key': API_KEY_JOBS}
        # response = requests.get('{}/job/{}'.format(API_URL, job_id), headers=headers)
        # available_jobs = response.json()
        # print(available_jobs)

        user = myID()
        user_id = user['id']

        addLikes(user_id, job_id)

        return json.dumps({'status':'OK'})

@app.route('/unlike', methods=['GET', 'POST'])
@is_logged_in
def unlike():

    if request.method == 'POST':
        job_id = request.form['id']

        deleteLikes(job_id)

        return json.dumps({'status':'OK'})

@app.route('/my_jobs')
@is_logged_in
def my_jobs():

    form_avatar = UploadAvatar(request.form)

    # Define variables to count jobs and companies availables
    company = []
    area = []
    areas = []
    company = []
    count_company = {}
    count_area = {}
    available_jobs = []

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, avatar, name, lastname FROM users WHERE username = %s", [session['username']])
    user_name = cur.fetchone()
    user_id = user_name['id']


    # Get user by username
    cur.execute("SELECT * FROM follow_company WHERE user_id = (%s)", [user_id])
    users = cur.fetchall()
    cur.close()

    if request.method == 'POST' and form_avatar.submit_avatar.data:
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('¡Error subiendo, intente denuevo!')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No se seleccionó ningún archivo 😞')
            return redirect(request.url)
        if file and allowed_file_avatar(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], session['username'] + filename))
            # Create Cursor
            cur = mysql.connection.cursor()

            # Execute
            cur.execute("UPDATE users SET avatar=%s WHERE username=%s",('uploads/' + session['username'] + filename, session['username']))

            # Commit to DB
            mysql.connection.commit()

            #Close connection
            cur.close()
            flash('Archivo subido de manera exitosa 😊')
            return redirect('/my_jobs')
        else:
            flash('Solo puedes subir archivos jpeg, jpg y png 🙁')
            return redirect(request.url)
    
    headers = {'X-Api-Key': API_KEY_JOBS}
    
    for user in users:
        response = requests.get('{}/job/{}'.format(API_URL, user['job_id']), headers=headers)
        available_jobs.append(response.json())

    print(available_jobs)
    
    if len(available_jobs) > 0:
        for available_job in available_jobs:
            area.append(str(available_job[0]['area']))
            company.append(str(available_job[0]['author']))

        companies = list(dict.fromkeys(company))
        companies.sort()

        areas = list(dict.fromkeys(area))
        areas.sort()

        for comp in companies:
            count = company.count(comp)
            count_company[comp] = count
            company_count = json.dumps(count_company)

        bar = request.args.to_dict()
        print(bar)


        for each_area in areas:
            count = area.count(each_area)
            count_area[each_area] = count
            area_count = json.dumps(count_area)
        
        area_count = json.loads(area_count)
        return render_template('my_jobs.html', available_jobs=available_jobs, areas=areas, area_count=area_count, companies=companies, company_count=company_count, form_avatar=form_avatar, avatar_url=user_name['avatar'], user=user_name['name'], lastname=user_name['lastname'])
    else:
        msg = 'No sigues ninguna oferta laboral 😕'
        return render_template('my_jobs.html', msg=msg, form_avatar=form_avatar, avatar_url=user_name['avatar'], user=user_name['name'], lastname=user_name['lastname'])

@app.route('/jobs', methods=['GET'])
@is_logged_in
def list_jobs():

    form_avatar = UploadAvatar(request.form)

    # Define variables to count jobs and companies availables
    company = []
    area = []
    areas = []
    company = []
    count_company = {}
    count_area = {}

    cur = mysql.connection.cursor()
    cur.execute("SELECT id, avatar, name, lastname FROM users WHERE username = %s", [session['username']])
    user_name = cur.fetchone()

    if request.method == 'POST' and form_avatar.submit_avatar.data:
        # check if the post request has the file part
        if 'file' not in request.files:
            flash('¡Error subiendo, intente denuevo!')
            return redirect(request.url)
        file = request.files['file']
        if file.filename == '':
            flash('No se seleccionó ningún archivo 😞')
            return redirect(request.url)
        if file and allowed_file_avatar(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], session['username'] + filename))
            # Create Cursor
            cur = mysql.connection.cursor()

            # Execute
            cur.execute("UPDATE users SET avatar=%s WHERE username=%s",('uploads/' + session['username'] + filename, session['username']))

            # Commit to DB
            mysql.connection.commit()

            #Close connection
            cur.close()
            flash('Archivo subido de manera exitosa 😊')
            return redirect('/my_jobs')
        else:
            flash('Solo puedes subir archivos jpeg, jpg y png 🙁')
            return redirect(request.url)

    headers = {'X-Api-Key': API_KEY_JOBS}

    response = requests.get('{}/jobs'.format(API_URL), headers=headers)
    available_jobs = response.json()
    if len(available_jobs) > 0:
        for available_job in available_jobs:
            area.append(str(available_job['area']))
            company.append(str(available_job['author']))
        
        companies = list(dict.fromkeys(company))
        companies.sort()

        areas = list(dict.fromkeys(area))
        areas.sort()

        for comp in companies:
            count = company.count(comp)
            count_company[comp] = count
            company_count = json.dumps(count_company)
        
        company_count = json.loads(company_count)

        bar = request.args.to_dict()
        print(bar)


        for each_area in areas:
            count = area.count(each_area)
            count_area[each_area] = count
            area_count = json.dumps(count_area)
        
        area_count = json.loads(area_count)

        # for work in areas:
        #     for available_job in available_jobs:
        #         if str(available_job['area']) == work:
        #             count_area[work].append(str(available_job['area']))
        #             total_work = json.dumps(count_area)

        # print(count_area)
        return render_template('jobs.html', available_jobs=available_jobs, areas=areas, area_count=area_count, companies=companies, company_count=company_count,  form_avatar=form_avatar, avatar_url=user_name['avatar'], user=user_name['name'], lastname=user_name['lastname'])
    else:
        msg = 'No hay ofertas laborales disponibles 😕'
        return render_template('jobs.html', msg=msg,  form_avatar=form_avatar, avatar_url=user_name['avatar'], user=user_name['name'], lastname=user_name['lastname'])


# Delete Article
@app.route('/delete_article/<string:id>', methods=['POST'])
@is_logged_in
def delete_article(id):
    # Create cursor
    cur = mysql.connection.cursor()

    # Execute
    cur.execute("DELETE FROM articles WHERE id = %s", [id])

    # Commit to DB
    mysql.connection.commit()

    #Close connection
    cur.close()

    flash('Article Deleted', 'success')

    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    app.secret_key='secret123'
    app.run(debug=True)
